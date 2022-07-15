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
        return struct.unpack("?", value)[0]
    # iOS seems to be quite permissive about bools in
    # integer formatted characteristics.
    elif len(value) == 1 and char.format in INT_TYPES:
        return int(struct.unpack("?", value)[0])
    elif char.format == CharacteristicFormats.uint8:
        return struct.unpack("B", value)[0]
    elif char.format == CharacteristicFormats.uint16:
        return struct.unpack("H", value)[0]
    elif char.format == CharacteristicFormats.uint32:
        return struct.unpack("I", value)[0]
    elif char.format == CharacteristicFormats.uint64:
        return struct.unpack("Q", value)[0]
    elif char.format == CharacteristicFormats.int:
        return struct.unpack("i", value)[0]
    elif char.format == CharacteristicFormats.float:
        return struct.unpack("f", value)[0]
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
        value = struct.pack("f", value)
    elif char.format == CharacteristicFormats.string:
        value = value.encode("utf-8")

    return bytes(value)
