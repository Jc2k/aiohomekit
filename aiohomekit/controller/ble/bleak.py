from __future__ import annotations

from typing import Any
import uuid

from bleak import BleakClient, BleakError
from bleak.backends.characteristic import BleakGATTCharacteristic
from bleak.backends.device import BLEDevice

from .const import HAP_MIN_REQUIRED_MTU, HAP_MIN_SHOULD_MTU

BLEAK_EXCEPTIONS = (AttributeError, BleakError)


class AIOHomeKitBleakClient(BleakClient):
    """Wrapper for bleak.BleakClient that auto discovers the max mtu."""

    def __init__(self, address_or_ble_device: BLEDevice | str) -> None:
        """Wrap bleak."""
        super().__init__(address_or_ble_device)
        self._discovered_mtu = 0

    @property
    def mtu_size(self) -> int:
        """Return the mtu size of the client."""
        # Nanoleaf light strips fail if we use an mtu > HAP_MIN_SHOULD_MTU
        return min(
            HAP_MIN_SHOULD_MTU,
            max(self._discovered_mtu, super().mtu_size, HAP_MIN_REQUIRED_MTU),
        )

    async def read_gatt_char(
        self,
        char_specifier: BleakGATTCharacteristic | int | str | uuid.UUID,
        **kwargs: Any,
    ) -> bytearray:
        """Read a GATT characteristic"""
        data = await super().read_gatt_char(char_specifier, **kwargs)
        data_len = len(data)
        if data_len > self._discovered_mtu:
            self._discovered_mtu = data_len
        return data
