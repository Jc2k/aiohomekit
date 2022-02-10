from __future__ import annotations

import logging
from typing import Any, AsyncIterable

from bleak import BleakScanner
from bleak.exc import BleakDBusError, BleakError

from aiohomekit.characteristic_cache import CharacteristicCacheType
from aiohomekit.controller.abstract import AbstractController
from aiohomekit.controller.ble.manufacturer_data import HomeKitAdvertisement
from aiohomekit.controller.ble.pairing import BlePairing
from aiohomekit.exceptions import AccessoryNotFoundError

from .discovery import BleDiscovery

logger = logging.getLogger(__name__)


class BleController(AbstractController):
    discoveries: dict[str, BleDiscovery]
    pairings: dict[str, BlePairing]
    aliases: dict[str, BlePairing]

    _scanner: BleakScanner | None

    def __init__(self, char_cache: CharacteristicCacheType):
        super().__init__(char_cache=char_cache)

    def _device_detected(self, device, advertisement_data):
        try:
            data = HomeKitAdvertisement.from_advertisement(device, advertisement_data)
        except ValueError:
            return

        if pairing := self.pairings.get(data.id):
            pairing._async_description_update(data)

        if data.id in self.discoveries:
            self.discoveries[data.id]._async_process_advertisement(data)
            return

        self.discoveries[data.id] = BleDiscovery(self, device, data)

    async def async_start(self) -> None:
        try:
            self._scanner = BleakScanner()
            self._scanner.register_detection_callback(self._device_detected)
            await self._scanner.start()
        except (BleakDBusError, BleakError) as e:
            logger.debug(
                "Failed to connect to start scanner, HAP-BLE not available: %s", str(e)
            )
            self._scanner = None

    async def async_stop(self, *args):
        if self._scanner:
            await self._scanner.stop()
            self._scanner.register_detection_callback(None)
            self._scanner = None

    async def async_find(self, device_id: str) -> BleDiscovery:
        if device_id in self.discoveries:
            return self.discoveries[device_id]

        raise AccessoryNotFoundError(f"Accessory with device id {device_id} not found")

    async def async_discover(self) -> AsyncIterable[BleDiscovery]:
        for device in self.discoveries.values():
            yield device

    def load_pairing(
        self, alias: str, pairing_data: dict[str, Any]
    ) -> BlePairing | None:
        if pairing_data["Connection"] != "BLE":
            return None

        if not (hkid := pairing_data.get("AccessoryPairingID")):
            return None

        pairing = self.pairings[hkid.lower()] = BlePairing(self, pairing_data)
        self.aliases[alias] = pairing

        return pairing
