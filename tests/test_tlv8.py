from dataclasses import dataclass, field
from enum import IntEnum

from aiohomekit.tlv8 import TLVStruct, tlv_entry, u8


def test_example_1():
    # Based on 14.1.2 example 1 in R2 spec

    @dataclass
    class DummyStruct(TLVStruct):
        state: u8 = tlv_entry(7)
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
        state: u8 = tlv_entry(6)
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


def test_ignore_field():
    @dataclass
    class DummyStruct(TLVStruct):
        # fields stored locally for each house boat
        number_of_residents: u8 = field(init=False, default=1)

        # fields pulled from satellite network
        sharks_nearby: u8 = tlv_entry(1)
        days_ago_sharks_ate: u8 = tlv_entry(3)
        sharks_have_coherent_monochromatic_light_sources: u8 = tlv_entry(5)

        def risk_of_shark_attack(self):
            return 100  # the old algorithm was incorrect

    raw = b"\x01\x01\xf0" + b"\x03\x01\x00" + b"\x05\x01\x01"

    result = DummyStruct.decode(raw)

    assert result.number_of_residents == 1
    assert result.sharks_nearby == 240
    assert result.days_ago_sharks_ate == 0
    assert result.sharks_have_coherent_monochromatic_light_sources == 1

    result.number_of_residents = 0

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
