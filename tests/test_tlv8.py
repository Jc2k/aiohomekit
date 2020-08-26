from dataclasses import dataclass
from enum import IntEnum

from aiohomekit.tlv8 import TLVStruct, tlv_entry


def test_example_1():
    # Based on 14.1.2 example 1 in R2 spec

    @dataclass
    class DummyStruct(TLVStruct):
        state: int = tlv_entry(7)
        message: str = tlv_entry(1)

    raw = b"\x07\x01\x03\x01\x05\x68\x65\x6c\x6c\x6f"

    result = DummyStruct.decode(raw)

    assert result.state == 3
    assert result.message == "hello"

    assert result.encode() == raw


def test_example_2():
    # Based on 14.1.2 example 1 in R2 spec

    @dataclass
    class DummyStruct(TLVStruct):
        state: int = tlv_entry(6)
        certificate: str = tlv_entry(9)
        identifier: str = tlv_entry(1)

    raw = (
        b"\x06\x01\x03\x09\xff"
        + b"a" * 255
        + b"\x09\x2d"
        + b"a" * 45
        + b"\x01\x05hello"
    )

    result = DummyStruct.decode(raw)

    assert result.state == 3
    assert result.certificate == "a" * 300
    assert result.identifier == "hello"

    assert result.encode() == raw


def test_int_enum():
    class FooValues(IntEnum):
        ACTIVE = 1
        INACTIVE = 0

    @dataclass
    class DummyStruct(TLVStruct):
        foo: FooValues = tlv_entry(1)

    result = DummyStruct.decode(b"\x01\x01\x01")
    assert result.foo == FooValues.ACTIVE

    assert DummyStruct(foo=FooValues.ACTIVE).encode() == b"\x01\x01\x01"
    assert DummyStruct(foo=FooValues.INACTIVE).encode() == b"\x01\x01\x00"
