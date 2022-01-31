#
# Copyright 2019 aiohomekit team
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
from __future__ import annotations

import argparse
from argparse import ArgumentParser, Namespace
import asyncio
import json
import locale
import logging
import pathlib
import re
import sys

from .controller import Controller
from .exceptions import HomeKitException

logger = logging.getLogger(__name__)

XDG_DATA_HOME = pathlib.Path.home() / ".local" / "share"
DEFAULT_PAIRING_FILE = XDG_DATA_HOME / "aiohomekit" / "pairing.json"


def pin_from_keyboard():
    read_pin = ""
    while re.match(r"^\d{3}-\d{2}-\d{3}$", read_pin) is None:
        read_pin = input("Enter device pin (XXX-YY-ZZZ): ")
    return read_pin


def setup_logging(level: None) -> None:
    """
    Set up the logging to use a decent format and the log level given as parameter.
    :param level: the log level used for the root logger
    """
    logging.basicConfig(
        format="%(asctime)s %(filename)s:%(lineno)04d %(levelname)s %(message)s"
    )
    if level:
        getattr(logging, level.upper())
        numeric_level = getattr(logging, level.upper(), None)
        if not isinstance(numeric_level, int):
            raise ValueError("Invalid log level: %s" % level)
        logging.getLogger().setLevel(numeric_level)


def add_log_arguments(parser: ArgumentParser) -> None:
    """
    Adds command line arguments to control logging behaviour.
    :param parser: The argparse.ArgumentParser object to add to.
    """
    parser.add_argument("--log", action="store", dest="loglevel")


def prepare_string(input_string):
    """
    Make a string save for printing in a terminal. The string get recoded using the terminals preferred locale and
    replacing the characters that cannot be encoded.
    :param input_string: the input string
    :return: the output string which is save for printing
    """
    return "{t}".format(
        t=input_string.encode(locale.getpreferredencoding(), errors="replace").decode()
    )


async def discover_ip(args):
    controller = Controller()
    for discovery in await controller.discover_ip(args.timeout):
        info = discovery.info

        if args.unpaired_only and info["sf"] == "0":
            continue

        print("Name: {name}".format(name=prepare_string(info["name"])))
        print(
            "Url: http_impl://{ip}:{port}".format(ip=info["address"], port=info["port"])
        )
        print("Configuration number (c#): {conf}".format(conf=info["c#"]))
        print(
            "Feature Flags (ff): {f} (Flag: {flags})".format(
                f=info["flags"], flags=info["ff"]
            )
        )
        print("Device ID (id): {id}".format(id=info["id"]))
        print("Model Name (md): {md}".format(md=prepare_string(info["md"])))
        print("Protocol Version (pv): {pv}".format(pv=info["pv"]))
        print("State Number (s#): {sn}".format(sn=info["s#"]))
        print(
            "Status Flags (sf): {sf} (Flag: {flags})".format(
                sf=info["statusflags"], flags=info["sf"]
            )
        )
        print(
            "Category Identifier (ci): {c} (Id: {ci})".format(
                c=info["category"], ci=info["ci"]
            )
        )
        print()

    return True


async def pair_ip(args):
    controller = Controller()

    try:
        controller.load_data(args.file)
    except Exception:
        logger.exception(f"Error while loading {args.file}")
        return False

    if args.alias in controller.get_pairings():
        print(f'"{args.alias}" is a already known alias')
        return False

    discovery = await controller.find_ip_by_device_id(args.device)

    try:
        finish_pairing = await discovery.start_pairing(args.alias)
    except HomeKitException as e:
        print(str(e))
        return False

    pin = args.pin if args.pin else pin_from_keyboard()

    try:
        pairing = await finish_pairing(pin)
    except HomeKitException as e:
        print(str(e))
        return False

    try:
        await pairing.list_accessories_and_characteristics()
    except HomeKitException as e:
        print(str(e))
        return False

    controller.save_data(args.file)

    print(f'Pairing for "{args.alias}" was established.')
    return True


async def get_accessories(args: Namespace) -> bool:
    controller = Controller()

    try:
        controller.load_data(args.file)
    except Exception:
        logger.exception(f"Error while loading {args.file}")
        return False

    if args.alias not in controller.get_pairings():
        print(f'"{args.alias}" is no known alias')
        return False

    try:
        pairing = controller.get_pairings()[args.alias]
        data = await pairing.list_accessories_and_characteristics()
        controller.save_data(args.file)
    except Exception:
        logging.exception("Error whilst fetching /accessories")
        return False

    # prepare output
    if args.output == "json":
        print(json.dumps(data, indent=4))
    elif args.output == "compact":
        for accessory in data:
            aid = accessory["aid"]
            for service in accessory["services"]:
                s_type = service["type"]
                s_iid = service["iid"]
                print(f"{aid}.{s_iid}: >{s_type}<")

                for characteristic in service["characteristics"]:
                    c_iid = characteristic["iid"]
                    value = characteristic.get("value", "")
                    c_type = characteristic["type"]
                    perms = ",".join(characteristic["perms"])
                    desc = characteristic.get("description", "")
                    print(f"  {aid}.{c_iid}: {value} ({desc}) >{c_type}< [{perms}]")
    return True


async def get_characteristics(args: Namespace) -> bool:
    controller = Controller()

    controller.load_data(args.file)
    if args.alias not in controller.get_pairings():
        print(f'"{args.alias}" is no known alias')
        return False

    pairing = controller.get_pairings()[args.alias]

    # convert the command line parameters to the required form
    characteristics = [
        (int(c.split(".")[0]), int(c.split(".")[1])) for c in args.characteristics
    ]

    # get the data
    try:
        data = await pairing.get_characteristics(
            characteristics,
            include_meta=args.meta,
            include_perms=args.perms,
            include_type=args.type,
            include_events=args.events,
        )
    except Exception:
        logging.exception("Error whilst fetching /accessories")
        return False

    # print the data
    tmp = {}
    for k in data:
        nk = str(k[0]) + "." + str(k[1])
        tmp[nk] = data[k]

    print(json.dumps(tmp, indent=4))
    return True


async def put_characteristics(args: Namespace) -> bool:
    controller = Controller(args.adapter)
    try:
        controller.load_data(args.file)
    except Exception:
        logger.exception("Error whilst loading pairing")
        return False

    if args.alias not in controller.get_pairings():
        print(f'"{args.alias}" is no known alias')
        return False

    try:
        pairing = controller.get_pairings()[args.alias]

        # FIXME use Service.build_update

        characteristics = [
            (
                int(c[0].split(".")[0]),  # the first part is the aid, must be int
                int(c[0].split(".")[1]),  # the second part is the iid, must be int
                c[1],
            )
            for c in args.characteristics
        ]
        results = await pairing.put_characteristics(characteristics)
    except Exception:
        logging.exception("Unhandled error whilst writing to device")
        return False

    for key, value in results.items():
        aid = key[0]
        iid = key[1]
        status = value["status"]
        desc = value["description"]
        # used to be < 0 but bluetooth le errors are > 0 and only success (= 0) needs to be checked
        if status != 0:
            print(
                "put_characteristics failed on {aid}.{iid} because: {reason} ({code})".format(
                    aid=aid, iid=iid, reason=desc, code=status
                )
            )
    return True


async def list_pairings(args: Namespace) -> bool:
    controller = Controller(args.adapter)
    controller.load_data(args.file)
    if args.alias not in controller.get_pairings():
        print(f'"{args.alias}" is no known alias')
        exit(-1)

    pairing = controller.get_pairings()[args.alias]
    try:
        pairings = await pairing.list_pairings()
    except Exception as e:
        print(e)
        logging.debug(e, exc_info=True)
        sys.exit(-1)

    for pairing in pairings:
        print("Pairing Id: {id}".format(id=pairing["pairingId"]))
        print("\tPublic Key: 0x{key}".format(key=pairing["publicKey"]))
        print(
            "\tPermissions: {perm} ({type})".format(
                perm=pairing["permissions"], type=pairing["controllerType"]
            )
        )

    return True


async def remove_pairing(args):
    controller = Controller(args.adapter)
    controller.load_data(args.file)
    if args.alias not in controller.get_pairings():
        print(f'"{args.alias}" is no known alias')
        return False

    pairing = controller.get_pairings()[args.alias]
    await pairing.remove_pairing(args.controllerPairingId)
    controller.save_data(args.file)
    print(f'Pairing for "{args.alias}" was removed.')
    return True


async def unpair(args):
    controller = Controller(args.adapter)
    controller.load_data(args.file)
    if args.alias not in controller.get_pairings():
        print(f'"{args.alias}" is no known alias')
        return False

    await controller.remove_pairing(args.alias)
    controller.save_data(args.file)
    print(f"Device {args.alias} was completely unpaired.")
    return True


async def get_events(args):
    controller = Controller()

    controller.load_data(args.file)
    if args.alias not in controller.get_pairings():
        print(f'"{args.alias}" is no known alias')
        return False

    pairing = controller.get_pairings()[args.alias]

    # convert the command line parameters to the required form
    characteristics = [
        (int(c.split(".")[0]), int(c.split(".")[1])) for c in args.characteristics
    ]

    def handler(data):
        # print the data
        tmp = {}
        for k in data:
            nk = str(k[0]) + "." + str(k[1])
            tmp[nk] = data[k]

        print(json.dumps(tmp, indent=4))

    pairing.dispatcher_connect(handler)

    results = await pairing.subscribe(characteristics)
    if results:
        for key, value in results.items():
            aid = key[0]
            iid = key[1]
            status = value["status"]
            desc = value["description"]
            if status < 0:
                print(
                    "watch failed on {aid}.{iid} because: {reason} ({code})".format(
                        aid=aid, iid=iid, reason=desc, code=status
                    )
                )
        return False

    while True:
        # get the data
        try:
            data = await pairing.get_characteristics(
                characteristics,
            )
            handler(data)
        except Exception:
            logging.exception("Error whilst fetching /accessories")
            return False

        await asyncio.sleep(10)

    return True


def setup_parser_for_pairing(parser: ArgumentParser) -> None:
    parser.add_argument(
        "-f",
        action="store",
        required=False,
        dest="file",
        default=DEFAULT_PAIRING_FILE,
        help="File with the pairing data",
    )
    parser.add_argument(
        "-a", action="store", required=True, dest="alias", help="alias for the pairing"
    )


async def main(argv: list[str] | None = None) -> None:
    argv = argv or sys.argv[1:]

    parser = argparse.ArgumentParser(
        description="aiohomekitctl",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--adapter",
        action="store",
        dest="adapter",
        default="hci0",
        help="the bluetooth adapter to be used (defaults to hci0)",
    )
    add_log_arguments(parser)

    subparsers = parser.add_subparsers(
        title="available commands", metavar="command [options ...]"
    )

    # discover_ip
    discover_parser = subparsers.add_parser(
        "discover-ip", help="Find HomeKit devices accessible by LAN/WiFi"
    )
    discover_parser.set_defaults(func=discover_ip)
    discover_parser.add_argument(
        "-t",
        action="store",
        required=False,
        dest="timeout",
        type=int,
        default=10,
        help="Number of seconds to wait",
    )
    discover_parser.add_argument(
        "-u",
        action="store_true",
        required=False,
        dest="unpaired_only",
        help="If activated, this option will show only unpaired HomeKit IP Devices",
    )

    # pair_ip
    pair_parser = subparsers.add_parser(
        "pair-ip", help="Pair with a HomeKit device accessible on your LAN/WiFi"
    )
    pair_parser.set_defaults(func=pair_ip)
    setup_parser_for_pairing(pair_parser)
    pair_parser.add_argument(
        "-d",
        action="store",
        required=True,
        dest="device",
        help="HomeKit Device ID (use discover to get it)",
    )
    pair_parser.add_argument(
        "-p",
        action="store",
        required=False,
        dest="pin",
        help="HomeKit configuration code",
    )

    # get_accessories - return all characteristics of all services of all accessories.
    get_accessories_parser = subparsers.add_parser(
        "accessories",
        help="List all accessories, services and characteristics for a paired device",
    )
    get_accessories_parser.set_defaults(func=get_accessories)
    setup_parser_for_pairing(get_accessories_parser)
    get_accessories_parser.add_argument(
        "-o",
        action="store",
        dest="output",
        default="compact",
        choices=["json", "compact"],
        help="Specify output format",
    )

    # get_characteristics - get only requested characteristics
    get_char_parser = subparsers.add_parser(
        "get",
        help="Read an up to date value from a characteristic of a paired device",
    )
    get_char_parser.set_defaults(func=get_characteristics)
    setup_parser_for_pairing(get_char_parser)
    get_char_parser.add_argument(
        "-c",
        action="append",
        required=True,
        dest="characteristics",
        help="Read characteristics, multiple characteristics can be given by repeating the option",
    )
    get_char_parser.add_argument(
        "-m",
        action="store_true",
        required=False,
        dest="meta",
        help="read out the meta data for the characteristics as well",
    )
    get_char_parser.add_argument(
        "-p",
        action="store_true",
        required=False,
        dest="perms",
        help="read out the permissions for the characteristics as well",
    )
    get_char_parser.add_argument(
        "-t",
        action="store_true",
        required=False,
        dest="type",
        help="read out the types for the characteristics as well",
    )
    get_char_parser.add_argument(
        "-e",
        action="store_true",
        required=False,
        dest="events",
        help="read out the events for the characteristics as well",
    )

    # put_characteristics - set characteristics values
    put_char_parser = subparsers.add_parser(
        "put", help="Write to a characteristic of a paired device"
    )
    put_char_parser.set_defaults(func=put_characteristics)
    setup_parser_for_pairing(put_char_parser)
    put_char_parser.add_argument(
        "-c",
        action="append",
        required=False,
        dest="characteristics",
        nargs=2,
        help="Use aid.iid value to change the value. Repeat to change multiple characteristics.",
    )

    get_events_parser = subparsers.add_parser(
        "watch", help="Monitor changes to characteristics on this device"
    )
    get_events_parser.set_defaults(func=get_events)
    setup_parser_for_pairing(get_events_parser)
    get_events_parser.add_argument(
        "-c",
        action="append",
        required=True,
        dest="characteristics",
        help="Read characteristics, multiple characteristics can be given by repeating the option",
    )

    # list_pairings - list all pairings
    list_pairings_parser = subparsers.add_parser(
        "list-pairings", help="List all pairings from a paired device"
    )
    list_pairings_parser.set_defaults(func=list_pairings)
    setup_parser_for_pairing(list_pairings_parser)

    # remove_pairing - remove sub pairing
    remove_pairing_parser = subparsers.add_parser(
        "remove-pairing", help="Remove a subpairing from a paired device"
    )
    remove_pairing_parser.set_defaults(func=remove_pairing)
    setup_parser_for_pairing(remove_pairing_parser)
    remove_pairing_parser.add_argument(
        "-i",
        action="store",
        required=True,
        dest="controllerPairingId",
        help="this pairing ID identifies the controller who should be removed from accessory",
    )

    # unpair - completely unpair the device
    unpair_parser = subparsers.add_parser(
        "unpair", help="Completely unpair this device"
    )
    unpair_parser.set_defaults(func=unpair)
    setup_parser_for_pairing(unpair_parser)

    args = parser.parse_args(argv)

    setup_logging(args.loglevel)

    if not hasattr(args, "func"):
        parser.print_help()
        sys.exit(1)

    if not await args.func(args):
        sys.exit(1)


def sync_main():
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    sync_main()
