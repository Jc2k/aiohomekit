from dataclasses import dataclass, field
from enum import IntEnum

from aiohomekit.tlv8 import TLVStruct, tlv_entry, u8, u64, u128


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

    raw = b"\x06\x01\x03\x09\xff" + b"a" * 255 + b"\x09\x2d" + b"a" * 45 + b"\x01\x05hello"

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


def test_int_64b():
    @dataclass
    class DummyStruct(TLVStruct):
        prefix: u64 = tlv_entry(48)

    raw = b"\x30\x08" + b"\xbb\xe8\xec<wS\xc8\xfd"

    result = DummyStruct.decode(raw)

    assert f"{result.prefix:X}" == "FDC853773CECE8BB"

    assert result.encode() == raw


def test_int_uuid():
    @dataclass
    class DummyStruct(TLVStruct):
        dummy_type: u128 = tlv_entry(16)

    raw = b"\x10\x10" + b"\x83\xc3*\xa6yS\xb1N\x90\xdetZ\xb4l:&"

    result = DummyStruct.decode(raw)

    assert f"{result.dummy_type:X}" == "263A6CB45A74DE904EB15379A62AC383"

    assert result.encode() == raw


def test_bytes():
    @dataclass
    class DummyStruct(TLVStruct):
        value: bytes = tlv_entry(160)

    raw = (
        b"\xa0\x12" + b"\x88\x01\x00\x34" + b"\x00\x01\x00\x05\x74\x68\x2f\x74\x63" + b"\x00\x03\x00\x27\x00"
    )

    result = DummyStruct.decode(raw)

    assert result.value == b"\x88\x01\x00\x34\x00\x01\x00\x05\x74\x68\x2f\x74\x63\x00\x03\x00\x27\x00"

    assert result.encode() == raw
