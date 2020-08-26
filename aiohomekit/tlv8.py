from dataclasses import field, fields
import enum
from functools import lru_cache
import struct
from typing import Any, Callable, Dict, TypeVar

SerializerCallback = Callable[[type, Any], bytes]
DeserializerCallback = Callable[[type, bytes], Any]
T = TypeVar("T")


class TlvParseException(Exception):
    """Raised upon parse error with some TLV"""

    pass


class TlvSerializeException(Exception):
    """Raised upon parse error with some TLV"""

    pass


def deserialize_int(value_type: type, value: bytes) -> int:
    return int.from_bytes(value, "little")


def deserialize_str(value_type: type, value: bytes) -> str:
    return value.decode("utf-8")


def deserialize_int_enum(value_type: type, value: bytes) -> enum.IntEnum:
    int_value = deserialize_int(value_type, value)
    return value_type(int_value)


def serialize_int(value_type: type, value: int) -> bytes:
    return struct.pack("B", value)


def serialize_str(value_type: type, value: str) -> bytes:
    return value.encode("utf-8")


def serialize_int_enum(value_type: type, value: enum.IntEnum) -> bytes:
    return serialize_int(value_type, int(value))


def tlv_entry(type: int, **kwargs):
    return field(metadata={"tlv_type": type, **kwargs})


@lru_cache(maxsize=100)
def find_serializer(py_type: type):
    superclasses = [py_type]
    if hasattr(type, "__mro__"):
        superclasses = py_type.__mro__

    for klass in superclasses:
        if klass in SERIALIZERS:
            return SERIALIZERS[klass]

    raise TlvSerializeException(f"Cannot serialize {py_type} to TLV8")


@lru_cache(maxsize=100)
def find_deserializer(py_type: type):
    superclasses = [py_type]
    if hasattr(type, "__mro__"):
        superclasses = py_type.__mro__

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
            tlv_type = struct_field.metadata["tlv_type"]
            py_type = struct_field.type

            serializer = find_serializer(py_type)
            encoded = serializer(py_type, getattr(self, struct_field.name))

            for offset in range(0, len(encoded), 255):
                chunk = encoded[offset : offset + 255]
                result.append(tlv_type)
                result.extend(struct.pack("B", len(chunk)))
                result.extend(chunk)

        return bytes(result)

    @classmethod
    def decode(cls: T, encoded_struct: bytes) -> T:
        kwargs = {}
        offset = 0

        # FIXME: Would by good if we could cache this per cls
        # And not rebuild it every time decode() is called
        tlv_types = {field.metadata["tlv_type"]: field for field in fields(cls)}

        while offset < len(encoded_struct):
            type = encoded_struct[offset]
            if type not in tlv_types:
                raise TlvParseException(f"Unknown TLV type {type} for {cls}")

            py_type = tlv_types[type].type
            deserializer = find_deserializer(py_type)

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

            kwargs[tlv_types[type].name] = deserializer(py_type, value)

            offset += 2 + length

        return cls(**kwargs)


DESERIALIZERS: Dict[type, DeserializerCallback] = {
    int: deserialize_int,
    str: deserialize_str,
    enum.IntEnum: deserialize_int_enum,
}

SERIALIZERS: Dict[type, SerializerCallback] = {
    int: serialize_int,
    str: serialize_str,
    enum.IntEnum: serialize_int_enum,
}
