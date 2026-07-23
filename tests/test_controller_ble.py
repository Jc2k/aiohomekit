from __future__ import annotations

from typing import Any
from unittest.mock import AsyncMock, patch

from bleak.backends.device import BLEDevice
from bleak.backends.scanner import AdvertisementData
from bleak.exc import BleakError
import pytest

from aiohomekit.characteristic_cache import CharacteristicCacheMemory
from aiohomekit.controller.ble.const import AdditionalParameterTypes
from aiohomekit.controller.ble.controller import BleController
from aiohomekit.controller.ble.pairing import BlePairing
from aiohomekit.model import Accessory
from aiohomekit.model.characteristics import Characteristic, CharacteristicsTypes
from aiohomekit.model.services import ServicesTypes
from aiohomekit.pdu import OpCode
from aiohomekit.protocol.tlv import TLV

BLE_PAIRING_DATA = {
    "AccessoryPairingID": "aa:bb:cc:dd:ee:ff",
    "AccessoryAddress": "AA:BB:CC:DD:EE:FF",
    "Connection": "BLE",
}

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


@pytest.fixture
def ble_pairing(ble_controller: BleController) -> BlePairing:
    return BlePairing(ble_controller, dict(BLE_PAIRING_DATA))


async def test_close_clears_client_when_dbus_connection_died(ble_pairing: BlePairing) -> None:
    """An EOFError from a dead dbus socket must not leave a stale client behind.

    If the client is not cleared its is_connected can report a stale True
    forever, and the connection would never be reestablished.
    """
    client = AsyncMock()
    client.is_connected = True
    client.disconnect.side_effect = EOFError("dbus connection died")
    ble_pairing.client = client

    await ble_pairing.close()

    client.disconnect.assert_awaited_once()
    assert ble_pairing.client is None


async def test_close_clears_client_on_bleak_error(ble_pairing: BlePairing) -> None:
    """A BleakError from disconnect still results in the client being cleared."""
    client = AsyncMock()
    client.is_connected = True
    client.disconnect.side_effect = BleakError("Disconnected mid flight")
    ble_pairing.client = client

    await ble_pairing.close()

    client.disconnect.assert_awaited_once()
    assert ble_pairing.client is None


async def test_get_characteristics_skips_missing_value_response(
    ble_pairing: BlePairing,
) -> None:
    """A success PDU without a value TLV must not fail the whole read.

    Some accessories, such as the UltraLoq Bolt, return a success PDU
    without a value for some characteristics; they are skipped so the
    rest of the accessory still works.
    """
    accessory = Accessory.create_with_info(
        "00:00:00:00:00:01", "Bolt", "UltraLoq", "Bolt Fingerprint", "0001", "0.1"
    )
    service = accessory.add_service(ServicesTypes.LIGHTBULB)
    good_char = service.add_char(CharacteristicsTypes.ON)
    bad_char = service.add_char(CharacteristicsTypes.BRIGHTNESS)

    async def fake_request_under_lock(
        opcode: OpCode, char: Characteristic, data: bytes | None = None
    ) -> bytes:
        if char is good_char:
            return TLV.encode_list([(AdditionalParameterTypes.Value.value, b"\x01")])
        return b""

    with patch.object(ble_pairing, "_async_request_under_lock", fake_request_under_lock):
        async with ble_pairing._operation_lock:
            results = await ble_pairing._get_characteristics_while_connected([good_char, bad_char])

    assert results == {(1, good_char.iid): {"value": True}}
