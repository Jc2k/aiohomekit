from __future__ import annotations

import uuid

from bleak import BleakClient, BleakError
from bleak.backends.characteristic import BleakGATTCharacteristic
from bleak.backends.device import BLEDevice

from .const import HAP_MIN_REQUIRED_MTU

BLEAK_EXCEPTIONS = (AttributeError, BleakError)
CHAR_DESCRIPTOR_ID = "DC46F0FE-81D2-4616-B5D9-6ABDD796939A"
CHAR_DESCRIPTOR_UUID = uuid.UUID(CHAR_DESCRIPTOR_ID)


class AIOHomeKitBleakClient(BleakClient):
    """Wrapper for bleak.BleakClient that auto discovers the max mtu."""

    def __init__(self, address_or_ble_device: BLEDevice | str) -> None:
        """Wrap bleak."""
        super().__init__(address_or_ble_device)
        self._char_cache: dict[tuple[str, str], BleakGATTCharacteristic] = {}
        self._iid_cache: dict[BleakGATTCharacteristic, int] = {}

    def get_characteristic(
        self, service_type: str, characteristic_type: str
    ) -> BleakGATTCharacteristic:
        """Get a characteristic from the cache or the BleakGATTServiceCollection."""
        if char := self._char_cache.get((service_type, characteristic_type)):
            return char
        char = self.services.get_service(service_type).get_characteristic(
            characteristic_type
        )
        self._char_cache[(service_type, characteristic_type)] = char
        return char

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
