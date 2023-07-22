from collections.abc import Iterable
import contextlib
import socket
from typing import Optional
from unittest.mock import patch

import pytest
from zeroconf import DNSQuestionType, Zeroconf
from zeroconf.asyncio import AsyncServiceInfo, AsyncZeroconf

from aiohomekit.characteristic_cache import CharacteristicCacheMemory
from aiohomekit.controller.ip.controller import IpController
from aiohomekit.exceptions import AccessoryNotFoundError
from aiohomekit.model.categories import Categories
from aiohomekit.model.status_flags import StatusFlags

HAP_TYPE_TCP = "_hap._tcp.local."
HAP_TYPE_UDP = "_hap._udp.local."
CLASS_IN = 1
TYPE_PTR = 12


class MockedAsyncServiceInfo(AsyncServiceInfo):
    async def async_request(
        self,
        zc: "Zeroconf",
        timeout: float,
        question_type: Optional[DNSQuestionType] = None,
    ) -> bool:
        return self.load_from_cache(zc)


def _get_mock_service_info():
    desc = {
        b"c#": b"1",
        b"id": b"00:00:01:00:00:02",
        b"md": b"unittest",
        b"s#": b"1",
        b"ci": b"5",
        b"sf": b"0",
    }
    return MockedAsyncServiceInfo(
        HAP_TYPE_TCP,
        f"foo.{HAP_TYPE_TCP}",
        addresses=[socket.inet_aton("127.0.0.1")],
        port=1234,
        properties=desc,
        weight=0,
        priority=0,
    )


@contextlib.contextmanager
def _install_mock_service_info(
    mock_asynczeroconf: AsyncZeroconf, info: MockedAsyncServiceInfo
) -> Iterable[AsyncServiceInfo]:
    zeroconf: Zeroconf = mock_asynczeroconf.zeroconf
    zeroconf.cache.async_add_records(
        [*info.dns_addresses(), info.dns_pointer(), info.dns_service(), info.dns_text()]
    )

    assert (
        zeroconf.cache.async_all_by_details(HAP_TYPE_TCP, TYPE_PTR, CLASS_IN)
        is not None
    )

    with patch("aiohomekit.zeroconf.AsyncServiceInfo", MockedAsyncServiceInfo):
        yield


async def test_discover_find_one(mock_asynczeroconf: AsyncZeroconf):
    controller = IpController(
        char_cache=CharacteristicCacheMemory(), zeroconf_instance=mock_asynczeroconf
    )
    with _install_mock_service_info(mock_asynczeroconf, _get_mock_service_info()):
        async with controller:
            result = await controller.async_find("00:00:01:00:00:02")
        await controller._async_update_from_cache(mock_asynczeroconf.zeroconf)

    assert result.description.id == "00:00:01:00:00:02"
    assert result.description.category == Categories.LIGHTBULB
    assert result.description.config_num == 1
    assert result.description.state_num == 1
    assert result.description.model == "unittest"
    assert result.description.status_flags == StatusFlags(0)
    assert result.paired is True


async def test_discover_find_one_unpaired(mock_asynczeroconf: AsyncZeroconf):
    controller = IpController(
        char_cache=CharacteristicCacheMemory(), zeroconf_instance=mock_asynczeroconf
    )

    svc = _get_mock_service_info()
    svc.properties[b"sf"] = b"1"
    svc._set_properties(svc.properties)
    with _install_mock_service_info(mock_asynczeroconf, svc):
        async with controller:
            result = await controller.async_find("00:00:01:00:00:02")
        await controller._async_update_from_cache(mock_asynczeroconf.zeroconf)

    assert result.description.id == "00:00:01:00:00:02"
    assert result.description.status_flags == StatusFlags.UNPAIRED
    assert result.paired is False


async def test_discover_find_none(mock_asynczeroconf):
    controller = IpController(
        char_cache=CharacteristicCacheMemory(), zeroconf_instance=mock_asynczeroconf
    )

    async with controller:
        with pytest.raises(AccessoryNotFoundError):
            await controller.async_find("00:00:00:00:00:00", timeout=0.001)


async def test_find_device_id_case_lower(mock_asynczeroconf: AsyncZeroconf):
    controller = IpController(
        char_cache=CharacteristicCacheMemory(), zeroconf_instance=mock_asynczeroconf
    )

    svc_info_1 = _get_mock_service_info()
    svc_info_1.properties[b"id"] = b"aa:aa:aa:aa:aa:aa"
    svc_info_1._set_properties(svc_info_1.properties)

    with _install_mock_service_info(mock_asynczeroconf, svc_info_1):
        async with controller:
            await controller._async_update_from_cache(mock_asynczeroconf.zeroconf)
            res = await controller.async_find("AA:AA:AA:AA:AA:AA")
            assert res.description.id == "aa:aa:aa:aa:aa:aa"

    svc_info_2 = _get_mock_service_info()
    svc_info_2.properties[b"id"] = b"aa:aa:aa:aa:aa:aa"
    svc_info_2._set_properties(svc_info_2.properties)

    with _install_mock_service_info(mock_asynczeroconf, svc_info_2):
        svc_info_2.properties[b"id"] = b"aa:aa:aa:aa:aa:aa"

        async with controller:
            await controller._async_update_from_cache(mock_asynczeroconf.zeroconf)
            res = await controller.async_find("aa:aa:aa:aa:aa:aa")
            assert res.description.id == "aa:aa:aa:aa:aa:aa"


async def test_find_device_id_case_upper(mock_asynczeroconf: AsyncZeroconf):
    controller = IpController(
        char_cache=CharacteristicCacheMemory(), zeroconf_instance=mock_asynczeroconf
    )

    svc_info = _get_mock_service_info()
    svc_info.properties[b"id"] = b"AA:AA:aa:aa:AA:AA"
    svc_info._set_properties(svc_info.properties)

    with _install_mock_service_info(mock_asynczeroconf, svc_info):
        async with controller:
            await controller._async_update_from_cache(mock_asynczeroconf.zeroconf)
            res = await controller.async_find("AA:AA:AA:AA:AA:AA")
            assert res.description.id == "aa:aa:aa:aa:aa:aa"

    svc_info = _get_mock_service_info()
    svc_info.properties[b"id"] = b"AA:AA:aa:aa:AA:AA"
    svc_info._set_properties(svc_info.properties)

    with _install_mock_service_info(mock_asynczeroconf, svc_info):
        async with controller:
            await controller._async_update_from_cache(mock_asynczeroconf.zeroconf)
            res = await controller.async_find("aa:aa:aa:aa:aa:aa")
            assert res.description.id == "aa:aa:aa:aa:aa:aa"


async def test_discover_discover_one(mock_asynczeroconf: AsyncZeroconf):
    controller = IpController(
        char_cache=CharacteristicCacheMemory(), zeroconf_instance=mock_asynczeroconf
    )

    srv_info = _get_mock_service_info()
    with _install_mock_service_info(mock_asynczeroconf, srv_info):
        async with controller:
            await controller._async_update_from_cache(mock_asynczeroconf.zeroconf)
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


async def test_discover_missing_csharp(mock_asynczeroconf: AsyncZeroconf):
    controller = IpController(
        char_cache=CharacteristicCacheMemory(), zeroconf_instance=mock_asynczeroconf
    )

    svc_info = _get_mock_service_info()
    del svc_info.properties[b"c#"]
    svc_info._set_properties(svc_info.properties)

    with _install_mock_service_info(mock_asynczeroconf, svc_info):
        async with controller:
            await controller._async_update_from_cache(mock_asynczeroconf.zeroconf)
            results = [d async for d in controller.async_discover()]

    assert results[0].description.id == "00:00:01:00:00:02"
    assert results[0].description.config_num == 0


async def test_discover_csharp_case(mock_asynczeroconf: AsyncZeroconf):
    controller = IpController(
        char_cache=CharacteristicCacheMemory(), zeroconf_instance=mock_asynczeroconf
    )

    svc_info = _get_mock_service_info()
    del svc_info.properties[b"c#"]
    svc_info.properties[b"C#"] = b"1"
    svc_info._set_properties(svc_info.properties)

    with _install_mock_service_info(mock_asynczeroconf, svc_info):
        async with controller:
            await controller._async_update_from_cache(mock_asynczeroconf.zeroconf)
            results = [d async for d in controller.async_discover()]

    assert results[0].description.config_num == 1


async def test_discover_device_id_case_lower(mock_asynczeroconf: AsyncZeroconf):
    controller = IpController(
        char_cache=CharacteristicCacheMemory(), zeroconf_instance=mock_asynczeroconf
    )

    svc_info = _get_mock_service_info()
    svc_info.properties[b"id"] = b"aa:aa:aa:aa:aa:aa"
    svc_info._set_properties(svc_info.properties)

    with _install_mock_service_info(mock_asynczeroconf, svc_info):
        async with controller:
            await controller._async_update_from_cache(mock_asynczeroconf.zeroconf)

            results = [d async for d in controller.async_discover()]

    assert results[0].description.id == "aa:aa:aa:aa:aa:aa"


async def test_discover_device_id_case_upper(mock_asynczeroconf: AsyncZeroconf):
    controller = IpController(
        char_cache=CharacteristicCacheMemory(), zeroconf_instance=mock_asynczeroconf
    )

    svc_info = _get_mock_service_info()
    svc_info.properties[b"id"] = b"AA:AA:aa:aa:AA:AA"
    svc_info._set_properties(svc_info.properties)

    with _install_mock_service_info(mock_asynczeroconf, svc_info):
        async with controller:
            await controller._async_update_from_cache(mock_asynczeroconf.zeroconf)

            results = [d async for d in controller.async_discover()]

    assert results[0].description.id == "aa:aa:aa:aa:aa:aa"
