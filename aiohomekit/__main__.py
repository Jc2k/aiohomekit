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
from collections.abc import AsyncIterator
import contextlib
import locale
import logging
import pathlib
import re
import sys

from zeroconf.asyncio import AsyncServiceBrowser, AsyncZeroconf

from aiohomekit.characteristic_cache import CharacteristicCacheFile
import aiohomekit.hkjson as hkjson

from .controller import Controller
from .exceptions import HomeKitException
from .zeroconf import ZeroconfServiceListener

logger = logging.getLogger(__name__)

XDG_DATA_HOME = pathlib.Path.home() / ".local" / "share"
DEFAULT_PAIRING_FILE = XDG_DATA_HOME / "aiohomekit" / "pairing.json"


@contextlib.asynccontextmanager
async def get_controller(args: argparse.Namespace) -> AsyncIterator[Controller]:
    charmap_path = pathlib.Path(args.file).parent / "charmap.json"

    zeroconf = AsyncZeroconf()

    controller = Controller(
        async_zeroconf_instance=zeroconf,
        char_cache=CharacteristicCacheFile(charmap_path),
    )

    try:
        controller.load_data(args.file)
    except Exception:
        logger.exception(f"Error while loading {args.file}")
        raise SystemExit

    async with zeroconf:
        listener = ZeroconfServiceListener()
        browser = AsyncServiceBrowser(
            zeroconf.zeroconf,
            [
                "_hap._tcp.local.",
                "_hap._udp.local.",
            ],
            listener=listener,
        )

        async with controller:
            yield controller

        await browser.async_cancel()


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


async def discover(args):
    async with get_controller(args) as controller:
        await asyncio.sleep(30)

        async for discovery in controller.async_discover(args.timeout):
            if args.unpaired_only and not discovery.paired:
                continue

            desc = discovery.description

            print(f"Name: {desc.name}")
            print(f"Device ID (id): {desc.id}")
            if hasattr(desc, "model"):
                print(f"Model Name (md): {desc.model}")
            if hasattr(desc, "feature_flags"):
                print(f"Feature Flags (ff): {desc.feature_flags!s}")
            if desc.status_flags:
                print(f"Status Flags (sf): {desc.status_flags!s}")
            print(f"Category (ci): {desc.category!s}")
            print(f"Configuration number (c#): {desc.config_num}")
            print(f"State Number (s#): {desc.state_num}")
            print()

    return True


async def pair(args):
    async with get_controller(args) as controller:
        if args.alias in controller.aliases:
            print(f'"{args.alias}" is a already known alias')
            return False

        discovery = await controller.async_find(args.device)

        try:
            finish_pairing = await discovery.async_start_pairing(args.alias)
        except HomeKitException as e:
            print(str(e))
            return False

        pin = args.pin if args.pin else pin_from_keyboard()

        try:
            await finish_pairing(pin)
        except HomeKitException as e:
            print(str(e))
            return False

        controller.save_data(args.file)

        print(f'Pairing for "{args.alias}" was established.')
    return True


async def get_accessories(args: Namespace) -> bool:
    async with get_controller(args) as controller:

        if args.alias not in controller.aliases:
            print(f'"{args.alias}" is no known alias')
            return False

        try:
            pairing = controller.aliases[args.alias]
            data = await pairing.list_accessories_and_characteristics()
            controller.save_data(args.file)
        except Exception:
            logging.exception("Error whilst fetching /accessories")
            return False

        # prepare output
        if args.output == "json":
            print(hkjson.dumps_indented(data))
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
    async with get_controller(args) as controller:

        if args.alias not in controller.aliases:
            print(f'"{args.alias}" is no known alias')
            return False

        pairing = controller.aliases[args.alias]

        # convert the command line parameters to the required form
        characteristics = [
            (int(c.split(".")[0]), int(c.split(".")[1])) for c in args.characteristics
        ]

        # get the data
        try:
            data = await pairing.get_characteristics(
                characteristics,
            )
        except Exception:
            logging.exception("Error whilst getting characteristic values")
            return False

        # print the data
        tmp = {}
        for k in data:
            nk = str(k[0]) + "." + str(k[1])
            tmp[nk] = data[k]

        print(hkjson.dumps_indented(tmp))

    return True


async def put_characteristics(args: Namespace) -> bool:
    async with get_controller(args) as controller:

        if args.alias not in controller.aliases:
            print(f'"{args.alias}" is no known alias')
            return False

        try:
            pairing = controller.aliases[args.alias]

            # FIXME use Service.build_update

            characteristics = [
                (
                    int(c[0].split(".")[0]),  # the first part is the aid, must be int
                    int(c[0].split(".")[1]),  # the second part is the iid, must be int
                    hkjson.loads(c[1]),
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


async def identify(args: Namespace) -> bool:
    async with get_controller(args) as controller:
        if args.alias not in controller.aliases:
            print(f'"{args.alias}" is no known alias')
            return False

        try:
            pairing = controller.aliases[args.alias]
            await pairing.identify()
        except Exception:
            logging.exception("Unhandled error whilst identifying device")
            return False

    return True


async def list_pairings(args: Namespace) -> bool:
    async with get_controller(args) as controller:
        if args.alias not in controller.aliases:
            print(f'"{args.alias}" is no known alias')
            exit(-1)

        pairing = controller.aliases[args.alias]
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
    async with get_controller(args) as controller:
        if args.alias not in controller.aliases:
            print(f'"{args.alias}" is no known alias')
            return False

        pairing = controller.aliases[args.alias]
        await pairing.remove_pairing(args.controllerPairingId)
        controller.save_data(args.file)
        print(f'Pairing for "{args.alias}" was removed.')
        return True


async def unpair(args):
    async with get_controller(args) as controller:
        if args.alias not in controller.aliases:
            print(f'"{args.alias}" is no known alias')
            return False

        await controller.remove_pairing(args.alias)
        controller.save_data(args.file)
        print(f"Device {args.alias} was completely unpaired.")
        return True


async def get_events(args):
    async with get_controller(args) as controller:
        if args.alias not in controller.aliases:
            print(f'"{args.alias}" is no known alias')
            return False

        pairing = controller.aliases[args.alias]

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

            print(hkjson.dumps_indented(tmp))

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
    parser.add_argument(
        "-f",
        action="store",
        required=False,
        dest="file",
        default=DEFAULT_PAIRING_FILE,
        help="File with the pairing data",
    )

    subparsers = parser.add_subparsers(
        title="available commands", metavar="command [options ...]"
    )

    # discover
    discover_parser = subparsers.add_parser(
        "discover", help="Find HomeKit devices accessible from this controller"
    )
    discover_parser.set_defaults(func=discover)
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
        help="If activated, this option will show only unpaired HomeKit devices",
    )

    # pair
    pair_parser = subparsers.add_parser(
        "pair", help="Pair with an unpaired HomeKit device"
    )
    pair_parser.set_defaults(func=pair)
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

    identify_parser = subparsers.add_parser("identify", help="Identify a paired device")
    identify_parser.set_defaults(func=identify)
    setup_parser_for_pairing(identify_parser)

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
