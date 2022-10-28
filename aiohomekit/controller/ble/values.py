from __future__ import annotations

import struct

from aiohomekit.model import Characteristic, CharacteristicFormats

INT_TYPES = {
    CharacteristicFormats.uint8,
    CharacteristicFormats.uint16,
    CharacteristicFormats.uint32,
    CharacteristicFormats.uint64,
    CharacteristicFormats.int,
}


def from_bytes(char: Characteristic, value: bytes) -> bool | str | float | int | bytes:
    if char.format == CharacteristicFormats.bool:
        return struct.unpack_from("?", value)[0]
    elif char.format == CharacteristicFormats.uint8:
        return struct.unpack_from("B", value)[0]
    elif char.format == CharacteristicFormats.uint16:
        return struct.unpack_from("H", value)[0]
    elif char.format == CharacteristicFormats.uint32:
        return struct.unpack_from("I", value)[0]
    elif char.format == CharacteristicFormats.uint64:
        return struct.unpack_from("Q", value)[0]
    elif char.format == CharacteristicFormats.int:
        return struct.unpack_from("i", value)[0]
    elif char.format == CharacteristicFormats.float:
        # FOR BLE float is 32 bit
        return struct.unpack_from("f", value)[0]
    elif char.format == CharacteristicFormats.string:
        return value.decode("utf-8")

    return value.hex()


def to_bytes(char: Characteristic, value: bool | str | float | int | bytes) -> bytes:
    if char.format == CharacteristicFormats.bool:
        value = struct.pack("?", value)
    elif char.format == CharacteristicFormats.uint8:
        value = struct.pack("B", value)
    elif char.format == CharacteristicFormats.uint16:
        value = struct.pack("H", value)
    elif char.format == CharacteristicFormats.uint32:
        value = struct.pack("I", value)
    elif char.format == CharacteristicFormats.uint64:
        value = struct.pack("Q", value)
    elif char.format == CharacteristicFormats.int:
        value = struct.pack("i", value)
    elif char.format == CharacteristicFormats.float:
        # FOR BLE float is 32 bit
        value = struct.pack("f", value)
    elif char.format == CharacteristicFormats.string:
        value = value.encode("utf-8")

    return bytes(value)
