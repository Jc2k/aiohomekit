from __future__ import annotations

from typing import Any
from unittest.mock import AsyncMock, patch

from bleak.backends.device import BLEDevice
from bleak.backends.scanner import AdvertisementData
from bleak.exc import BleakError
import pytest

from aiohomekit.characteristic_cache import CharacteristicCacheMemory
from aiohomekit.controller.ble.controller import BleController

ADVERTISEMENT_DATA_DEFAULTS = {
    "local_name": "",
    "manufacturer_data": {},
    "service_data": {},
    "service_uuids": [],
    "rssi": -127,
    "platform_data": ((),),
    "tx_power": -127,
}

BLE_DEVICE_DEFAULTS = {
    "name": None,
    "rssi": -127,
    "details": None,
}


def generate_advertisement_data(**kwargs: Any) -> AdvertisementData:
    """Generate advertisement data with defaults."""
    new = kwargs.copy()
    for key, value in ADVERTISEMENT_DATA_DEFAULTS.items():
        new.setdefault(key, value)
    return AdvertisementData(**new)


def generate_ble_device(
    address: str | None = None,
    name: str | None = None,
    details: Any | None = None,
    rssi: int | None = None,
    **kwargs: Any,
) -> BLEDevice:
    """Generate a BLEDevice with defaults."""
    new = kwargs.copy()
    if address is not None:
        new["address"] = address
    if name is not None:
        new["name"] = name
    if details is not None:
        new["details"] = details
    if rssi is not None:
        new["rssi"] = rssi
    for key, value in BLE_DEVICE_DEFAULTS.items():
        new.setdefault(key, value)
    return BLEDevice(**new)


@pytest.fixture
def ble_controller() -> BleController:
    return BleController(CharacteristicCacheMemory())


def test_discovery_with_none_name(ble_controller: BleController) -> None:
    ble_device_with_short_name = generate_ble_device(name="Nam", address="00:00:00:00:00:00")
    ble_device_with_name = generate_ble_device(name="Name in Full", address="00:00:00:00:00:00")
    ble_device = generate_ble_device(
        name=None,
        address="00:00:00:00:00:00",
    )
    adv = generate_advertisement_data(
        local_name=None,
        manufacturer_data={76: b"\x061\x00\x80\xe7\x14j74\x06\x00\x9f!\x04\x02<\xb9\xeb\x0e"},
    )
    ble_controller._device_detected(ble_device, adv)
    assert "80:e7:14:6a:37:34" in ble_controller.discoveries
    ble_controller._device_detected(ble_device_with_short_name, adv)
    assert "80:e7:14:6a:37:34" in ble_controller.discoveries
    assert ble_controller.discoveries["80:e7:14:6a:37:34"].name == "Nam (00:00:00:00:00:00)"
    ble_controller._device_detected(ble_device, adv)
    assert ble_controller.discoveries["80:e7:14:6a:37:34"].name == "Nam (00:00:00:00:00:00)"
    ble_controller._device_detected(ble_device_with_name, adv)
    assert ble_controller.discoveries["80:e7:14:6a:37:34"].name == "Name in Full (00:00:00:00:00:00)"
    ble_controller._device_detected(ble_device_with_short_name, adv)
    assert ble_controller.discoveries["80:e7:14:6a:37:34"].name == "Name in Full (00:00:00:00:00:00)"


async def test_async_start_and_stop(ble_controller: BleController) -> None:
    """The scanner is constructed with the detection callback and started."""
    scanner = AsyncMock()
    with patch("aiohomekit.controller.ble.controller.BleakScanner", return_value=scanner) as scanner_class:
        await ble_controller.async_start()

    scanner_class.assert_called_once_with(detection_callback=ble_controller._device_detected)
    scanner.start.assert_awaited_once()
    assert ble_controller._scanner is scanner

    await ble_controller.async_stop()
    scanner.stop.assert_awaited_once()
    assert ble_controller._scanner is None


async def test_async_start_already_started(ble_controller: BleController) -> None:
    """A second async_start does not replace the running scanner."""
    scanner = AsyncMock()
    with patch("aiohomekit.controller.ble.controller.BleakScanner", return_value=scanner) as scanner_class:
        await ble_controller.async_start()
        await ble_controller.async_start()

    scanner_class.assert_called_once()
    scanner.start.assert_awaited_once()
    assert ble_controller._scanner is scanner


async def test_async_start_scanner_init_fails(ble_controller: BleController) -> None:
    """HAP-BLE is unavailable when the scanner cannot be constructed."""
    with patch(
        "aiohomekit.controller.ble.controller.BleakScanner",
        side_effect=BleakError("No powered adapter"),
    ):
        await ble_controller.async_start()

    assert ble_controller._scanner is None


async def test_async_start_scanner_start_fails(ble_controller: BleController) -> None:
    """HAP-BLE is unavailable when the scanner fails to start."""
    scanner = AsyncMock()
    scanner.start.side_effect = BleakError("No powered adapter")
    with patch("aiohomekit.controller.ble.controller.BleakScanner", return_value=scanner):
        await ble_controller.async_start()

    assert ble_controller._scanner is None
