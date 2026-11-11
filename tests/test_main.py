"""Test the AIO CLI variant."""

import json
from contextlib import asynccontextmanager
from unittest import mock

import pytest

from aiohomekit import Controller
from aiohomekit.__main__ import main
from aiohomekit.characteristic_cache import CharacteristicCacheMemory
from aiohomekit.controller.abstract import TransportType
from aiohomekit.controller.ip import IpDiscovery
from aiohomekit.controller.ip.controller import IpController
from aiohomekit.model.categories import Categories
from aiohomekit.zeroconf import HomeKitService


async def test_help():
    with mock.patch("sys.stdout") as stdout:
        with pytest.raises(SystemExit):
            await main(["-h"])
    printed = stdout.write.call_args[0][0]

    assert printed.startswith("usage: ")
    assert "discover" in printed


@pytest.mark.parametrize("existing_alias", [False, True], ids=["new-file", "preserves-existing"])
async def test_pair_persists_transport_pairing(tmp_path, monkeypatch, mock_asynczeroconf, existing_alias):
    """The pairing returned by the transport must be saved by the CLI controller."""
    pairing_file = tmp_path / "pairing.json"
    pairing_data = {
        "AccessoryPairingID": "00:01:02:03:04:05",
        "AccessoryLTPK": "11" * 32,
        "iOSPairingId": "00000000-0000-0000-0000-000000000001",
        "iOSDeviceLTPK": "22" * 32,
        "iOSDeviceLTSK": "33" * 32,
    }
    expected = {
        "new": {
            **pairing_data,
            "AccessoryIP": "127.0.0.1",
            "AccessoryIPs": ["127.0.0.1"],
            "AccessoryPort": 1234,
            "Connection": "IP",
        }
    }
    if existing_alias:
        expected["existing"] = {
            **pairing_data,
            "AccessoryPairingID": "00:01:02:03:04:06",
            "AccessoryIP": "127.0.0.2",
            "AccessoryPort": 1234,
            "Connection": "IP",
        }
        pairing_file.write_text(json.dumps({"existing": expected["existing"]}))

    cache = CharacteristicCacheMemory()
    controller = Controller(char_cache=cache)
    transport = IpController(char_cache=cache, zeroconf_instance=mock_asynczeroconf)
    controller.transports[TransportType.IP] = transport
    discovery = IpDiscovery(
        transport,
        HomeKitService(
            name="Test",
            id="00:01:02:03:04:05",
            model="Test",
            feature_flags=0,
            status_flags=1,
            config_num=0,
            state_num=0,
            category=Categories.OTHER,
            protocol_version="1.0",
            type="_hap._tcp.local.",
            address="127.0.0.1",
            addresses=["127.0.0.1"],
            port=1234,
        ),
    )

    @asynccontextmanager
    async def get_controller(args):
        controller.load_data(args.file)
        yield controller

    def pair_setup_result(result):
        yield [], []
        return result

    # Keep real discovery registration and file serialization, but no network or cryptographic handshake.
    monkeypatch.setattr("aiohomekit.__main__.get_controller", get_controller)
    monkeypatch.setattr(controller, "async_find", mock.AsyncMock(return_value=discovery))
    with (
        mock.patch.object(discovery, "connection", autospec=True),
        mock.patch(
            "aiohomekit.controller.ip.discovery.perform_pair_setup_part1",
            return_value=pair_setup_result((b"salt", b"public-key")),
        ),
        mock.patch(
            "aiohomekit.controller.ip.discovery.perform_pair_setup_part2",
            return_value=pair_setup_result(pairing_data),
        ),
    ):
        await main(
            ["-f", str(pairing_file), "pair", "-a", "new", "-d", discovery.description.id, "-p", "111-22-333"]
        )

    assert json.loads(pairing_file.read_text()) == expected


async def test_get_accessories(pairing):
    with mock.patch("sys.stdout") as stdout:
        await main(["-f", "tests-pairing.json", "accessories", "-a", "alias"])
    printed = stdout.write.call_args_list[0][0][0]
    assert printed.startswith("1.1: >0000003E-0000-1000-8000-0026BB765291")

    with mock.patch("sys.stdout") as stdout:
        await main(["-f", "tests-pairing.json", "accessories", "-a", "alias", "-o", "json"])
    printed = stdout.write.call_args_list[0][0][0]
    accessories = json.loads(printed)
    assert accessories[0]["aid"] == 1
    assert accessories[0]["services"][0]["iid"] == 1
    assert accessories[0]["services"][0]["characteristics"][0]["iid"] == 2


async def test_get_characteristic(pairing):
    with mock.patch("sys.stdout") as stdout:
        await main(["-f", "tests-pairing.json", "get", "-a", "alias", "-c", "1.9"])
    printed = stdout.write.call_args_list[0][0][0]
    assert json.loads(printed) == {"1.9": {"value": False}}


async def test_put_characteristic(pairing):
    with mock.patch("sys.stdout"):
        await main(["-f", "tests-pairing.json", "put", "-a", "alias", "-c", "1.9", "true"])

    characteristics = await pairing.get_characteristics([(1, 9)])
    assert characteristics[(1, 9)] == {"value": True}


async def test_list_pairings(pairing):
    with mock.patch("sys.stdout") as stdout:
        await main(["-f", "tests-pairing.json", "list-pairings", "-a", "alias"])
    printed = "".join(write[0][0] for write in stdout.write.call_args_list)
    assert printed == (
        "Pairing Id: decc6fa3-de3e-41c9-adba-ef7409821bfc\n"
        "\tPublic Key: 0xd708df2fbf4a8779669f0ccd43f4962d6d49e4274f88b1292f822edc3bcf8ed8\n"
        "\tPermissions: 1 (admin)\n"
    )
