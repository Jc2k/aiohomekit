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


async def test_discover_find_one_unpaired(mock_asynczeroconf):
    controller = IpController(
        char_cache=CharacteristicCacheMemory(), zeroconf_instance=mock_asynczeroconf
    )

    with _install_mock_service_info(mock_asynczeroconf) as svc:
        svc.properties[b"sf"] = b"1"

        result = await controller.async_find("00:00:01:00:00:02")

    assert result.description.id == "00:00:01:00:00:02"
    assert result.description.status_flags == StatusFlags.UNPAIRED
    assert result.paired is False


async def test_discover_find_none(mock_asynczeroconf):
    controller = IpController(
        char_cache=CharacteristicCacheMemory(), zeroconf_instance=mock_asynczeroconf
    )

    with pytest.raises(AccessoryNotFoundError):
        await controller.async_find("00:00:00:00:00:00")


async def test_find_device_id_case_lower(mock_asynczeroconf):
    controller = IpController(
        char_cache=CharacteristicCacheMemory(), zeroconf_instance=mock_asynczeroconf
    )

    with _install_mock_service_info(mock_asynczeroconf) as svc_info:
        svc_info.properties[b"id"] = b"aa:aa:aa:aa:aa:aa"

        res = await controller.async_find("AA:AA:AA:AA:AA:AA")
        assert res.description.id == "aa:aa:aa:aa:aa:aa"

    with _install_mock_service_info(mock_asynczeroconf) as svc_info:
        svc_info.properties[b"id"] = b"aa:aa:aa:aa:aa:aa"

        res = await controller.async_find("aa:aa:aa:aa:aa:aa")
        assert res.description.id == "aa:aa:aa:aa:aa:aa"


async def test_find_device_id_case_upper(mock_asynczeroconf):
    controller = IpController(
        char_cache=CharacteristicCacheMemory(), zeroconf_instance=mock_asynczeroconf
    )

    with _install_mock_service_info(mock_asynczeroconf) as svc_info:
        svc_info.properties[b"id"] = b"AA:AA:aa:aa:AA:AA"

        res = await controller.async_find("AA:AA:AA:AA:AA:AA")
        assert res.description.id == "aa:aa:aa:aa:aa:aa"

    with _install_mock_service_info(mock_asynczeroconf) as svc_info:
        svc_info.properties[b"id"] = b"AA:AA:aa:aa:AA:AA"

        res = await controller.async_find("aa:aa:aa:aa:aa:aa")
        assert res.description.id == "aa:aa:aa:aa:aa:aa"


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


async def test_discover_missing_csharp(mock_asynczeroconf):
    controller = IpController(
        char_cache=CharacteristicCacheMemory(), zeroconf_instance=mock_asynczeroconf
    )

    with _install_mock_service_info(mock_asynczeroconf) as svc_info:
        del svc_info.properties[b"c#"]
        results = [d async for d in controller.async_discover()]

    assert results[0].description.id == "00:00:01:00:00:02"
    assert results[0].description.config_num == 0


async def test_discover_csharp_case(mock_asynczeroconf):
    controller = IpController(
        char_cache=CharacteristicCacheMemory(), zeroconf_instance=mock_asynczeroconf
    )

    with _install_mock_service_info(mock_asynczeroconf) as svc_info:
        del svc_info.properties[b"c#"]
        svc_info.properties[b"C#"] = b"1"

        results = [d async for d in controller.async_discover()]

    assert results[0].description.config_num == 1


async def test_discover_device_id_case_lower(mock_asynczeroconf):
    controller = IpController(
        char_cache=CharacteristicCacheMemory(), zeroconf_instance=mock_asynczeroconf
    )

    with _install_mock_service_info(mock_asynczeroconf) as svc_info:
        svc_info.properties[b"id"] = b"aa:aa:aa:aa:aa:aa"

        results = [d async for d in controller.async_discover()]

    assert results[0].description.id == "aa:aa:aa:aa:aa:aa"


async def test_discover_device_id_case_upper(mock_asynczeroconf):
    controller = IpController(
        char_cache=CharacteristicCacheMemory(), zeroconf_instance=mock_asynczeroconf
    )

    with _install_mock_service_info(mock_asynczeroconf) as svc_info:
        svc_info.properties[b"id"] = b"AA:AA:aa:aa:AA:AA"

        results = [d async for d in controller.async_discover()]

    assert results[0].description.id == "aa:aa:aa:aa:aa:aa"
