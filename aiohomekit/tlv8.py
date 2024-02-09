from __future__ import annotations

from collections import abc
from collections.abc import Iterable, Sequence
from dataclasses import field, fields
import enum
from functools import lru_cache
import struct
from typing import Any, Callable, ClassVar, Generic, TypeVar, _GenericAlias

SerializerCallback = Callable[[type, Any], bytes]
DeserializerCallback = Callable[[type, bytes], Any]
T = TypeVar("T")


class u8(int):
    pass


class u16(int):
    pass


class bu16(int):
    pass


class u32(int):
    pass


class u64(int):
    pass


class u128(int):
    pass


def get_origin(tp):
    """
    Returns the containing type

    get_origin(int) == None
    get_origin(Sequence[int]) == collections.abc.Sequence
    """
    if isinstance(tp, _GenericAlias):
        return tp.__origin__ if tp.__origin__ is not ClassVar else None
    if tp is Generic:
        return Generic
    return None


class TlvParseException(Exception):
    """Raised upon parse error with some TLV"""

    pass


class TlvSerializeException(Exception):
    """Raised upon parse error with some TLV"""

    pass


def tlv_iterator(encoded_struct: bytes) -> Iterable:
    offset = 0
    while offset < len(encoded_struct):
        type = encoded_struct[offset]
        length = encoded_struct[offset + 1]
        value = encoded_struct[offset + 2 :][:length]

        # If length is 255 the next chunks may be part of same value
        # Iterate until the type changes
        while length == 255:
            peek_offset = offset + 2 + length
            if encoded_struct[peek_offset] != type:
                break
            offset = peek_offset
            length = encoded_struct[offset + 1]
            value += encoded_struct[offset + 2 :][:length]

        yield offset, type, length, value

        offset += 2 + length


def tlv_array(encoded_array: bytes, separator: int = 0) -> Iterable[bytes]:
    start = 0

    for offset, type, length, chunk_value in tlv_iterator(encoded_array):
        if type == separator:
            yield encoded_array[start:offset]
            start = offset + 2
            continue

    item = encoded_array[start:]
    if item:
        yield item


def deserialize_u8(value_type: type, value: bytes) -> int:
    return int.from_bytes(value, "little")


def deserialize_u16(value_type: type, value: bytes) -> int:
    return int.from_bytes(value, "little")


def deserialize_bu16(value_type: type, value: bytes) -> int:
    return int.from_bytes(value, "big")


def deserialize_u32(value_type: type, value: bytes) -> int:
    return int.from_bytes(value, "little")


def deserialize_u64(value_type: type, value: bytes) -> int:
    return int.from_bytes(value, "little")


def deserialize_u128(value_type: type, value: bytes) -> int:
    return int.from_bytes(value, "little")


def deserialize_str(value_type: type, value: bytes) -> str:
    return value.decode("utf-8")


def deserialize_bytes(value_type: type, value: bytes) -> bytes:
    return value


def deserialize_int_enum(value_type: type, value: bytes) -> enum.IntEnum:
    int_value = deserialize_u8(value_type, value)
    return value_type(int_value)


def deserialize_tlv_struct(value_type: type, value: bytes) -> TLVStruct:
    return value_type.decode(value)


def deserialize_typing_sequence(value_type: type, value: bytes) -> Sequence[TLVStruct]:
    inner_type = value_type.__args__[0]

    results = []
    for inner_value in tlv_array(value):
        fn = find_deserializer(inner_type)
        results.append(fn(inner_type, inner_value))

    return results


def serialize_u8(value_type: type, value: int) -> bytes:
    return struct.pack("B", value)


def serialize_u16(value_type: type, value: int) -> bytes:
    return struct.pack("H", value)


def serialize_bu16(value_type: type, value: int) -> bytes:
    return struct.pack(">H", value)


def serialize_u32(value_type: type, value: int) -> bytes:
    return struct.pack("I", value)


def serialize_u64(value_type: type, value: int) -> bytes:
    return struct.pack("Q", value)


def serialize_u128(value_type: type, value: int) -> bytes:
    return value.to_bytes(length=16, byteorder="little")


def serialize_str(value_type: type, value: str) -> bytes:
    return value.encode("utf-8")


def serialize_bytes(value_type: type, value: bytes) -> bytes:
    return value


def serialize_int_enum(value_type: type, value: enum.IntEnum) -> bytes:
    return serialize_u8(value_type, int(value))


def serialize_tlv_struct(value_type: type, value: TLVStruct) -> bytes:
    return value.encode()


def serialize_typing_sequence(value_type: type, value: Sequence) -> bytes:
    if not value:
        return b""

    value_iter = iter(value)

    result = bytearray()
    result.extend(next(value_iter).encode())

    for val in value_iter:
        result.extend(b"\x00\x00")
        result.extend(val.encode())

    return bytes(result)


def tlv_entry(type: int, **kwargs):
    return field(default=None, metadata={"tlv_type": type, **kwargs})


@lru_cache(maxsize=100)
def find_serializer(py_type: type):
    if get_origin(py_type):
        superclasses = [get_origin(py_type)]
    elif hasattr(py_type, "__mro__"):
        superclasses = py_type.__mro__
    else:
        superclasses = [py_type]

    for klass in superclasses:
        if klass in SERIALIZERS:
            return SERIALIZERS[klass]

    raise TlvSerializeException(f"Cannot serialize {py_type} to TLV8")


@lru_cache(maxsize=100)
def find_deserializer(py_type: type):
    if get_origin(py_type):
        superclasses = [get_origin(py_type)]
    elif hasattr(py_type, "__mro__"):
        superclasses = py_type.__mro__
    else:
        superclasses = [py_type]

    for klass in superclasses:
        if klass in DESERIALIZERS:
            return DESERIALIZERS[klass]

    raise TlvParseException(f"Cannot deserialize TLV type {type} into {py_type}")


class TLVStruct:
    """
    A mixin that adds TLV8 encoding and decoding to dataclasses.
    """

    def encode(self) -> bytes:
        result = bytearray()

        for struct_field in fields(self):
            if not struct_field.init:
                continue
            value = getattr(self, struct_field.name)

            if value is None:
                continue

            tlv_type = struct_field.metadata["tlv_type"]
            py_type = struct_field.type

            serializer = find_serializer(py_type)
            encoded = serializer(py_type, value)

            for offset in range(0, len(encoded), 255):
                chunk = encoded[offset : offset + 255]
                result.append(tlv_type)
                result.extend(struct.pack("B", len(chunk)))
                result.extend(chunk)

        return bytes(result)

    @classmethod
    @lru_cache(maxsize=None)
    def _tlv_types(cls: T) -> dict:
        """Return the TLV types for this class."""
        return {
            field.metadata["tlv_type"]: field for field in fields(cls) if field.init
        }

    @classmethod
    def decode(cls: T, encoded_struct: bytes) -> T:
        kwargs = {}
        offset = 0

        tlv_types = cls._tlv_types()

        for offset, type, length, value in tlv_iterator(encoded_struct):
            if type not in tlv_types:
                raise TlvParseException(f"Unknown TLV type {type} for {cls}")

            py_type = tlv_types[type].type
            deserializer = find_deserializer(py_type)

            kwargs[tlv_types[type].name] = deserializer(py_type, value)

        return cls(**kwargs)


DESERIALIZERS: dict[type, DeserializerCallback] = {
    bu16: deserialize_bu16,
    u8: deserialize_u8,
    u16: deserialize_u16,
    u32: deserialize_u32,
    u64: deserialize_u64,
    u128: deserialize_u128,
    str: deserialize_str,
    enum.IntEnum: deserialize_int_enum,
    TLVStruct: deserialize_tlv_struct,
    abc.Sequence: deserialize_typing_sequence,
    bytes: deserialize_bytes,
}

SERIALIZERS: dict[type, SerializerCallback] = {
    bu16: serialize_bu16,
    u8: serialize_u8,
    u16: serialize_u16,
    u32: serialize_u32,
    u64: serialize_u64,
    u128: serialize_u128,
    str: serialize_str,
    enum.IntEnum: serialize_int_enum,
    TLVStruct: serialize_tlv_struct,
    abc.Sequence: serialize_typing_sequence,
    bytes: serialize_bytes,
}
