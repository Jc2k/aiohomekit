from __future__ import annotations

from functools import lru_cache
import logging
from typing import Any
import uuid

from bleak.backends.characteristic import BleakGATTCharacteristic
from bleak.backends.device import BLEDevice
from bleak_retry_connector import BleakClientWithServiceCache

from .const import HAP_MIN_REQUIRED_MTU

CHAR_DESCRIPTOR_ID = "DC46F0FE-81D2-4616-B5D9-6ABDD796939A"
CHAR_DESCRIPTOR_UUID = uuid.UUID(CHAR_DESCRIPTOR_ID)

logger = logging.getLogger(__name__)
ATT_HEADER_SIZE = 3


@lru_cache(maxsize=64, typed=True)
def _determine_fragment_size(
    address: str,
    mtu_size: int,
    additional_overhead_size: int,
    handle: BleakGATTCharacteristic,
) -> int:
    """Determine the fragment size for a characteristic based on the MTU."""
    # Newer bleak, not currently released
    if max_write_without_response_size := getattr(
        handle, "max_write_without_response_size", None
    ):
        logger.debug(
            "%s: Bleak max_write_without_response_size: %s, mtu_size-3: %s",
            address,
            max_write_without_response_size,
            mtu_size - ATT_HEADER_SIZE,
        )
        fragment_size = max(max_write_without_response_size, mtu_size - ATT_HEADER_SIZE)
    # Bleak 0.15.1 and below
    elif (
        (char_obj := getattr(handle, "obj", None))
        and isinstance(char_obj, dict)
        and (char_mtu := char_obj.get("MTU"))
    ):
        logger.debug(
            "%s: Bleak obj MTU: %s, client.mtu_size: %s",
            address,
            char_mtu,
            mtu_size,
        )
        fragment_size = max(char_mtu, mtu_size) - ATT_HEADER_SIZE
    else:
        logger.debug(
            "%s: No bleak obj MTU or max_write_without_response_size, using client.mtu_size-3: %s",
            address,
            mtu_size - ATT_HEADER_SIZE,
        )
        fragment_size = mtu_size - ATT_HEADER_SIZE

    if additional_overhead_size:
        # Secure session means an extra 16 bytes of overhead
        fragment_size -= additional_overhead_size

    logger.debug("%s: Using fragment size: %s", address, fragment_size)

    return fragment_size


class AIOHomeKitBleakClient(BleakClientWithServiceCache):
    """Wrapper for bleak.BleakClient that auto discovers the max mtu."""

    def __init__(self, address_or_ble_device: BLEDevice | str, **kwargs: Any) -> None:
        """Wrap bleak."""
        super().__init__(address_or_ble_device, **kwargs)
        self._char_cache: dict[tuple[str, str], BleakGATTCharacteristic] = {}
        self._iid_cache: dict[BleakGATTCharacteristic, int] = {}

    def get_characteristic(
        self, service_uuid: str, characteristic_uuid: str
    ) -> BleakGATTCharacteristic:
        """Get a characteristic from the cache or the BleakGATTServiceCollection.

        We need to do the linear searching ourselves because the BleakGATTServiceCollection
        calls can raise BleakError if there are more than one matching service or characteristic
        and we want to match the service and characteristic together.
        """
        cache_key = (service_uuid, characteristic_uuid)
        if char := self._char_cache.get(cache_key):
            return char
        uuid_lower = service_uuid.lower()
        service_matched = False
        for service in self.services.services.values():
            if service.uuid.lower() == uuid_lower:
                service_matched = True
                for char in service.characteristics:
                    if char.uuid.lower() == characteristic_uuid.lower():
                        self._char_cache[cache_key] = char
                        return char
        if not service_matched:
            available_services = [
                service.uuid for service in self.services.services.values()
            ]
            raise ValueError(
                f"Service {service_uuid} not found, available services: {available_services}"
            )
        available_chars = [char.uuid for char in service.characteristics]
        raise ValueError(
            f"Characteristic {characteristic_uuid} not found, available characteristics: {available_chars}"
        )

    async def get_characteristic_iid(
        self: AIOHomeKitBleakClient, char: BleakGATTCharacteristic
    ) -> int | None:
        """Get the iid of a characteristic."""
        if iid := self._iid_cache.get(char):
            return iid
        iid_handle = char.get_descriptor(CHAR_DESCRIPTOR_UUID)
        if iid_handle is None:
            return None
        value = bytes(await self.read_gatt_descriptor(iid_handle.handle))
        iid = int.from_bytes(value, byteorder="little")
        self._iid_cache[char] = iid
        return iid

    @property
    def mtu_size(self) -> int:
        """Return the mtu size of the client."""
        return max(super().mtu_size, HAP_MIN_REQUIRED_MTU)

    def determine_fragment_size(
        self,
        additional_overhead_size: int,
        handle: BleakGATTCharacteristic,
    ) -> int:
        """Determine the fragment size for a characteristic based on the MTU."""
        return _determine_fragment_size(
            self.address,
            self.mtu_size,
            additional_overhead_size,
            handle,
        )
