from __future__ import annotations

import logging
from typing import AsyncIterable

from bleak import BleakScanner

from aiohomekit.controller.abstract import AbstractController
from aiohomekit.controller.ble.manufacturer_data import ManufacturerData
from aiohomekit.controller.ble.pairing import BlePairing
from aiohomekit.exceptions import AccessoryNotFoundError

from .discovery import BleDiscovery

logger = logging.getLogger(__name__)


class BleController(AbstractController):
    discoveries: dict[str, BleDiscovery]
    pairings: dict[str, BlePairing]

    def __init__(self):
        super().__init__()

        self._scanner = BleakScanner()

    def _device_detected(self, device, advertisement_data):
        if not (mfr_data := advertisement_data.manufacturer_data):
            return

        if not (apple_data := mfr_data.get(76)):
            return

        if apple_data[0] != 0x06:
            return

        data = ManufacturerData.from_bytes(apple_data)

        if data.device_id in self.discoveries:
            self.discoveries[data.device_id]._async_process_advertisement(data)
            return

        self.discoveries[data.device_id] = BleDiscovery(self, device, data)

    async def async_start(self) -> None:
        self._scanner.register_detection_callback(self._device_detected)
        await self._scanner.start()

    async def async_stop(self, *args):
        await self._scanner.stop()
        self._scanner.register_detection_callback(None)

    async def async_find(self, device_id: str) -> BleDiscovery:
        if device_id in self.discoveries:
            return self.discoveries[device_id]

        raise AccessoryNotFoundError(f"Accessory with device id {device_id} not found")

    async def async_discover(self) -> AsyncIterable[BleDiscovery]:
        for device in self.discoveries.values():
            yield device
