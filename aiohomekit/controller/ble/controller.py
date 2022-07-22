from __future__ import annotations

import asyncio
import logging
from typing import AsyncIterable

from bleak import BleakScanner
from bleak.backends.device import BLEDevice
from bleak.backends.scanner import AdvertisementData
from bleak.exc import BleakDBusError, BleakError

from aiohomekit.characteristic_cache import CharacteristicCacheType
from aiohomekit.controller.abstract import AbstractController, AbstractPairingData
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

    def __init__(
        self,
        char_cache: CharacteristicCacheType,
        bleak_scanner_instance: BleakScanner | None = None,
    ) -> None:
        super().__init__(char_cache=char_cache)
        self._scanner = bleak_scanner_instance
        self._ble_futures: dict[str, list[asyncio.Future[BLEDevice]]] = {}

    def _device_detected(
        self, device: BLEDevice, advertisement_data: AdvertisementData
    ) -> None:
        try:
            data = HomeKitAdvertisement.from_advertisement(device, advertisement_data)
        except ValueError:
            return

        if pairing := self.pairings.get(data.id):
            pairing._async_description_update(data)
            pairing._async_ble_device_update(device)

        if futures := self._ble_futures.get(data.address):
            discovery = BleDiscovery(self, device, data)
            logger.debug("BLE device for %s found, fulfilling futures", data.address)
            for future in futures:
                future.set_result(discovery)
            futures.clear()

        if data.id in self.discoveries:
            self.discoveries[data.id]._async_process_advertisement(data)
            return

        self.discoveries[data.id] = BleDiscovery(self, device, data)

    async def async_start(self) -> None:
        logger.debug("Starting BLE controller with instance: %s", self._scanner)
        if not self._scanner:
            try:
                self._scanner = BleakScanner()
            except (FileNotFoundError, BleakDBusError, BleakError) as e:
                logger.debug(
                    "Failed to init scanner, HAP-BLE not available: %s", str(e)
                )
                self._scanner = None
                return

        try:
            self._scanner.register_detection_callback(self._device_detected)
            await self._scanner.start()
        except (FileNotFoundError, BleakDBusError, BleakError) as e:
            logger.debug("Failed to start scanner, HAP-BLE not available: %s", str(e))
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

    async def async_get_discovery(
        self, address: str, timeout: int
    ) -> BleDiscovery | None:
        """Get a discovery by address."""
        if discovery := self.discoveries.get(address):
            logger.debug("Discovery for %s already found", address)
            return discovery

        logger.debug(
            "Discovery for address %s not found, waiting for advertisement with timeout: %s",
            address,
            timeout,
        )
        future = asyncio.Future()
        self._ble_futures.setdefault(address, []).append(future)
        try:
            return await asyncio.wait_for(future, timeout=timeout)
        except asyncio.TimeoutError:
            logger.debug(
                "Timed out after %s waiting for discovery with address %s",
                timeout,
                address,
            )
            return None
        finally:
            if address not in self._ble_futures:
                return
            if future in self._ble_futures[address]:
                self._ble_futures[address].remove(future)
            if not self._ble_futures[address]:
                del self._ble_futures[address]

    def load_pairing(
        self, alias: str, pairing_data: AbstractPairingData
    ) -> BlePairing | None:
        if pairing_data["Connection"] != "BLE":
            return None

        if not (hkid := pairing_data.get("AccessoryPairingID")):
            return None

        id_ = hkid.lower()
        device: BLEDevice | None = None
        description: HomeKitAdvertisement | None = None

        if discovery := self.discoveries.get(id_):
            device = discovery.device
            description = discovery.description

        pairing = self.pairings[id_] = BlePairing(
            self, pairing_data, device=device, description=description
        )
        self.aliases[alias] = pairing

        return pairing
