from dataclasses import dataclass

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
