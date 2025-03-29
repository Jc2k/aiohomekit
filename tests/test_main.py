"""Test the AIO CLI variant."""

import json
from unittest import mock

import pytest

from aiohomekit.__main__ import main


async def test_help():
    with mock.patch("sys.stdout") as stdout:
        with pytest.raises(SystemExit):
            await main(["-h"])
    printed = stdout.write.call_args[0][0]

    assert printed.startswith("usage: ")
    assert "discover" in printed


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
