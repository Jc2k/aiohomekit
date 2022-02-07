from __future__ import annotations

import asyncio
import logging

from bleak import BleakClient, BleakScanner

from aiohomekit.controller.ble.manufacturer_data import ManufacturerData
from aiohomekit.model import CharacteristicsTypes, ServicesTypes
from aiohomekit.model.feature_flags import FeatureFlags

from .client import char_read, get_characteristic, get_characteristic_iid
from .discovery import BleDiscovery

logger = logging.getLogger(__name__)


class BleController:
    devices: dict[str, BleDiscovery]

    def __init__(self):
        self.devices = {}

        self._scanner = BleakScanner()

    def _device_detected(self, device, advertisement_data):
        if not (mfr_data := advertisement_data.manufacturer_data):
            return

        if not (apple_data := mfr_data.get(76)):
            return

        if apple_data[0] != 0x06:
            return

        data = ManufacturerData.from_bytes(apple_data)

        if data.device_id in self.devices:
            self.devices[data.device_id]._async_process_advertisement(data)
            return

        asyncio.create_task(self._async_device_added(device, data))

    async def _async_device_added(self, device, data):
        async with BleakClient(device) as client:
            ff_char = get_characteristic(
                client,
                ServicesTypes.PAIRING,
                CharacteristicsTypes.PAIRING_FEATURES,
            )
            ff_iid = await get_characteristic_iid(client, ff_char)
            ff_raw = await char_read(client, None, None, ff_char.handle, ff_iid)
            ff = FeatureFlags(ff_raw[0])

        self.devices[data.device_id] = BleDiscovery(self, device, data, ff)

    async def __aenter__(self) -> BleController:
        self._scanner.register_detection_callback(self._device_detected)
        await self._scanner.start()
        return self

    async def __aexit__(self, *args):
        await self._scanner.stop()
        self._scanner.register_detection_callback(None)
