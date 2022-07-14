import contextlib
import socket
from typing import Iterable
from unittest.mock import MagicMock, patch

import pytest
from zeroconf.asyncio import AsyncServiceInfo

from aiohomekit.characteristic_cache import CharacteristicCacheMemory
from aiohomekit.controller.ip.controller import IpController
from aiohomekit.exceptions import AccessoryNotFoundError
from aiohomekit.model.categories import Categories
from aiohomekit.model.status_flags import StatusFlags


@contextlib.contextmanager
def _install_mock_service_info(mock_asynczeroconf) -> Iterable[AsyncServiceInfo]:
    desc = {
        b"c#": b"1",
        b"id": b"00:00:01:00:00:02",
        b"md": b"unittest",
        b"s#": b"1",
        b"ci": b"5",
        b"sf": b"0",
    }

    info = AsyncServiceInfo(
        "_hap._tcp.local.",
        "foo._hap._tcp.local.",
        addresses=[socket.inet_aton("127.0.0.1")],
        port=1234,
        properties=desc,
        weight=0,
        priority=0,
    )

    mock_asynczeroconf.zeroconf.cache = MagicMock(
        get_all_by_details=MagicMock(
            return_value=[
                MagicMock(alias="foo._hap._tcp.local."),
            ]
        )
    )

    with patch("aiohomekit.zeroconf.AsyncServiceInfo", side_effect=[info]):
        yield info


async def test_discover_find_one(mock_asynczeroconf):
    controller = IpController(
        char_cache=CharacteristicCacheMemory(), zeroconf_instance=mock_asynczeroconf
    )

    with _install_mock_service_info(mock_asynczeroconf):
        result = await controller.async_find("00:00:01:00:00:02")

    assert result.description.id == "00:00:01:00:00:02"
    assert result.description.category == Categories.LIGHTBULB
    assert result.description.config_num == 1
    assert result.description.state_num == 1
    assert result.description.model == "unittest"
    assert result.description.status_flags == StatusFlags(0)
    assert result.paired is True


async def test_discover_find_none(mock_asynczeroconf):
    controller = IpController(
        char_cache=CharacteristicCacheMemory(), zeroconf_instance=mock_asynczeroconf
    )

    with pytest.raises(AccessoryNotFoundError):
        await controller.async_find("00:00:00:00:00:00")


async def test_discover_discover_one(mock_asynczeroconf):
    controller = IpController(
        char_cache=CharacteristicCacheMemory(), zeroconf_instance=mock_asynczeroconf
    )

    with _install_mock_service_info(mock_asynczeroconf):
        results = [d async for d in controller.async_discover()]

    assert results[0].description.id == "00:00:01:00:00:02"
    assert results[0].description.category == Categories.LIGHTBULB
    assert results[0].description.config_num == 1
    assert results[0].description.state_num == 1
    assert results[0].description.model == "unittest"
    assert results[0].description.status_flags == StatusFlags(0)
    assert results[0].paired is True


async def test_discover_none(mock_asynczeroconf):
    controller = IpController(
        char_cache=CharacteristicCacheMemory(), zeroconf_instance=mock_asynczeroconf
    )

    results = [d async for d in controller.async_discover()]
    assert results == []
