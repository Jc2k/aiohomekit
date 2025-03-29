from aiohomekit.controller.coap.pdu import (
    OpCode,
    PDUStatus,
    decode_all_pdus,
    decode_pdu,
    encode_all_pdus,
    encode_pdu,
)


def test_encode_without_data():
    req_pdu = encode_pdu(OpCode.CHAR_READ, 0x10, 0x2022, b"")

    assert req_pdu == b"\x00\x03\x10\x22\x20\x00\x00"


def test_encode_with_data():
    req_pdu = encode_pdu(OpCode.CHAR_WRITE, 0x20, 0x1234, b"\x01\x02\x03\x04")

    assert req_pdu == b"\x00\x02\x20\x34\x12\x04\x00\x01\x02\x03\x04"


def test_encode_all_without_data():
    req_pdu = encode_all_pdus(OpCode.CHAR_READ, [0x10, 0x11], [b"", b""])

    assert req_pdu == b"\x00\x03\x00\x10\x00\x00\x00" + b"\x00\x03\x01\x11\x00\x00\x00"


def test_encode_all_with_data():
    req_pdu = encode_all_pdus(
        OpCode.CHAR_WRITE, [0x12, 0x13], [b"\x88\x88", b"\x99\x99\x99\x99"]
    )

    assert (
        req_pdu
        == b"\x00\x02\x00\x12\x00\x02\x00\x88\x88"
        + b"\x00\x02\x01\x13\x00\x04\x00\x99\x99\x99\x99"
    )


def test_decode_without_data():
    res_pdu = b"\x02\x40\x00\x00\x00"
    res_len, res_val = decode_pdu(0x40, res_pdu)

    assert res_len == 0
    assert res_val == b""


def test_decode_with_data():
    res_pdu = b"\x02\x50\x00\x06\x00\x01\x01\x01\x02\x01\x00"
    res_len, res_val = decode_pdu(0x50, res_pdu)

    assert res_len == 6
    assert res_val == b"\x01\x01\x01\x02\x01\x00"


def test_decode_all_without_data():
    res_pdu = b"\x02\x20\x00\x00\x00" + b"\x02\x21\x00\x00\x00"
    res = decode_all_pdus(0x20, res_pdu)

    assert len(res) == 2
    assert isinstance(res[0], bytes)
    assert isinstance(res[1], bytes)
    assert len(res[0]) == 0
    assert len(res[1]) == 0


def test_decode_all_with_data():
    res_pdu = b"\x02\x30\x00\x02\x00\x01\x00" + b"\x02\x31\x00\x02\x00\x02\x00"
    res = decode_all_pdus(0x30, res_pdu)

    assert len(res) == 2
    assert isinstance(res[0], bytes)
    assert isinstance(res[1], bytes)
    assert res[0] == b"\x01\x00"
    assert res[1] == b"\x02\x00"


def test_decode_all_with_single_bad_tid():
    res_pdu = (
        b"\x02\x40\x00\x02\x00\x03\x00"
        + b"\x02\x99\x00\x02\x00\x04\x00"
        + b"\x02\x42\x00\x00\x00"
    )
    res = decode_all_pdus(0x40, res_pdu)

    assert len(res) == 3
    assert isinstance(res[0], bytes)
    assert isinstance(res[1], PDUStatus)
    assert isinstance(res[2], bytes)
    assert res[0] == b"\x03\x00"
    assert res[1] == PDUStatus.TID_MISMATCH
    assert len(res[2]) == 0


def test_decode_all_with_single_status_error():
    res_pdu = (
        b"\x02\x50\x00\x00\x00"
        + b"\x02\x51\x06\x00\x00"
        + b"\x02\x52\x00\x02\x00\x05\x00"
    )
    res = decode_all_pdus(0x50, res_pdu)

    assert len(res) == 3
    assert isinstance(res[0], bytes)
    assert isinstance(res[1], PDUStatus)
    assert isinstance(res[2], bytes)
    assert len(res[0]) == 0
    assert res[1] == PDUStatus.INVALID_REQUEST
    assert res[2] == b"\x05\x00"


def test_decode_all_with_single_bad_control():
    res_pdu = (
        b"\x02\x50\x00\x00\x00"
        + b"\x08\x51\x00\x00\x00"
        + b"\x02\x52\x00\x02\x00\x06\x00"
    )
    res = decode_all_pdus(0x50, res_pdu)

    assert len(res) == 3
    assert isinstance(res[0], bytes)
    assert isinstance(res[1], PDUStatus)
    assert isinstance(res[2], bytes)
    assert len(res[0]) == 0
    assert res[1] == PDUStatus.BAD_CONTROL
    assert res[2] == b"\x06\x00"


def test_decode_with_bad_tid():
    res_pdu = b"\x02\x99\x00\x00\x00"
    res_len, res_val = decode_pdu(0x60, res_pdu)

    assert res_len == 0
    assert res_val == PDUStatus.TID_MISMATCH


def test_decode_with_status_error():
    res_pdu = b"\x02\x99\x06\x00\x00"
    res_len, res_val = decode_pdu(0x99, res_pdu)

    assert res_len == 0
    assert isinstance(res_val, PDUStatus)
    assert res_val == PDUStatus.INVALID_REQUEST


def test_decode_with_bad_control():
    res_pdu = b"\xcc\x99\x00\x00\x00"
    res_len, res_val = decode_pdu(0x99, res_pdu)

    assert res_len == 0
    assert res_val == PDUStatus.BAD_CONTROL
