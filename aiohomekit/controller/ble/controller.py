from __future__ import annotations

import logging

from bleak import BleakScanner

from aiohomekit.controller.ble.manufacturer_data import ManufacturerData

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

        self.devices[data.device_id] = BleDiscovery(self, device, data)

    async def __aenter__(self) -> BleController:
        self._scanner.register_detection_callback(self._device_detected)
        await self._scanner.start()
        return self

    async def __aexit__(self, *args):
        await self._scanner.stop()
        self._scanner.register_detection_callback(None)
