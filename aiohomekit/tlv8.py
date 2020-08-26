from dataclasses import field, fields
import struct


class TlvParseException(Exception):
    """Raised upon parse error with some TLV"""

    pass


class TlvSerializeException(Exception):
    """Raised upon parse error with some TLV"""

    pass


def deserialize_int(value: bytes) -> int:
    return int.from_bytes(value, "little")


def deserialize_str(value: bytes) -> str:
    return value.decode("utf-8")


def serialize_int(value: int) -> bytes:
    return struct.pack("B", value)


def serialize_str(value: str) -> bytes:
    return value.encode("utf-8")


def tlv_entry(type, **kwargs):
    return field(metadata={"tlv_type": type, **kwargs})


class TLVStruct:
    """
    A mixin that adds TLV8 encoding and decoding to dataclasses.
    """

    def encode(self) -> bytes:
        result = bytearray()

        for struct_field in fields(self):
            tlv_type = struct_field.metadata["tlv_type"]
            py_type = struct_field.type

            if py_type not in SERIALIZERS:
                raise TlvSerializeException(f"Cannot serialize {py_type} to TLV8")

            encoded = SERIALIZERS[py_type](getattr(self, struct_field.name))

            for offset in range(0, len(encoded), 255):
                chunk = encoded[offset : offset + 255]
                result.append(tlv_type)
                result.extend(struct.pack("B", len(chunk)))
                result.extend(chunk)

        return bytes(result)

    @classmethod
    def decode(cls, encoded_struct: bytes) -> "TLVStruct":
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
            if py_type not in DESERIALIZERS:
                raise TlvParseException(
                    f"Cannot deserialize TLV type {type} into {py_type}"
                )

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

            kwargs[tlv_types[type].name] = DESERIALIZERS[py_type](value)

            offset += 2 + length

        return cls(**kwargs)


DESERIALIZERS = {
    int: deserialize_int,
    str: deserialize_str,
}

SERIALIZERS = {
    int: serialize_int,
    str: serialize_str,
}
