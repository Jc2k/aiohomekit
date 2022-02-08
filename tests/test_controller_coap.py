import pytest

from aiohomekit.controller.coap.connection import CoAPHomeKitConnection
from aiohomekit.controller.coap.pdu import PDUStatus
from aiohomekit.controller.coap.structs import Pdu09Database

database_nanoleaf_bulb = bytes.fromhex(
    """
18ff19ff1a02010016ff15f10702010006013e100014e61314\
050202000401140a0220000c070100002701000000001314050203000401\
200a0210000c071900002701000000001314050204000401210a0210000c\
071900002701000000001314050205000401230a0210000c071900002701\
000000001314050206000401300a0210000c071900002701000000001314\
050207000401520a0210000c071900002701000000001314050208000401\
530a0210000c0719000027010000000013230502090004103b94f9856afd\
c3ba40437fac1188ab340a0250000c07190000270100000000131505020a\
00040220020a0250000c071b0000270100000000153d18ff070219ff1000\
0601a20f16ff0204001000142e1314050211000401a50a0210000c071b00\
002701000000001314050212000401370a0210000c071900002701000000\
001569070220000601551000145e13140502220004014c0a0203000c071b\
000027010000000013140502230004014e0a0203000c071b000027010000\
000013140502240004014f0a0201000c0704000027010000000013140502\
25000401500a0230000c071b000027010000000015ff070230000601430f\
020100100014ff1314050231000401a50a0210000c071b00002701000000\
001314050232000401230a0210000c071900002701000000001314050233\
000401250a02b0030c18ff0701000019ff270100000000131e16ff050237\
000401ce0a02b0030c07080000270100000d0899000000d6010000000013\
1e050234000401080a02b0030c071000ad270100000d0800000000640000\
000000132305023c000410bdeeeece71000fa1374da1cf02198ea20a0270\
000c071b0000270100000000131505023900040244010a0210000c071b00\
00270100000000131505023800040243010a0230000c071b000027010000\
0000131905023a0004024b020a15620290030c07040000270100000d0200\
14510200001324050235000401130a02b0030c07140063270100000d0800\
0000000000b4430e040000803f000013240502360004012f0a0218ffb003\
0c07140019ffad270100000d0800000016ff000000c8420e040000803f00\
0015ab07027000060201071000149f1314050271000401a50a0210000c07\
1b0000270100000000131505027400040206070a0210000c071900002701\
00000000131b05027300040202070a0210000c07060000270100000d0400\
001f000000131b05027500040203070a0290030c07060000270100000d04\
00007f00000013150502760004022b020a0210000c070100002701000000\
00131505027700040204070a0230000c071b000027010000000015770702\
000a060239021000146b13140502040a0401a50a0210000c071b00002701\
00000000131f0502010a04023a184e020a0210000c070819440000270100\
000d08000000001636ffffff03000013150502020a04023c020a0211000c\
071b000027010000000013150502050a04024a020a0290030c0708000027\
010000"""
)


@pytest.fixture
def coap_controller():
    controller = CoAPHomeKitConnection(None, "any", 1234)
    controller.info = Pdu09Database.decode(database_nanoleaf_bulb)
    return controller


def test_write_characteristics(coap_controller):
    values = [
        # On
        (1, 51, True),
        # Brightness
        (1, 52, 100),
        # Hue
        (1, 53, 360.0),
        # Saturation
        (1, 54, 100.0),
    ]

    tlv_values = coap_controller._write_characteristics_enter(values)

    assert len(tlv_values) == 4
    assert tlv_values[0] == b"\x01\x01\x01"
    assert tlv_values[1] == b"\x01\x04\x64\x00\x00\x00"
    assert tlv_values[2] == b"\x01\x04\x00\x00\xB4\x43"
    assert tlv_values[3] == b"\x01\x04\x00\x00\xC8\x42"

    results = coap_controller._write_characteristics_exit(values, [b""] * len(values))

    assert len(results) == 0


def test_read_characteristics(coap_controller):
    ids = (
        # On
        (1, 51),
        # Brightness
        (1, 52),
        # Hue
        (1, 53),
        # Saturation
        (1, 54),
    )
    pdu_results = [
        b"\x01\x01\x01",
        b"\x01\x04\x64\x00\x00\x00",
        b"\x01\x04\x00\x00\xB4\x43",
        b"\x01\x04\x00\x00\xC8\x42",
    ]

    results = coap_controller._read_characteristics_exit(ids, pdu_results)

    assert len(results) == 4
    assert results[(1, 51)]["value"] is True
    assert results[(1, 52)]["value"] == 100
    assert results[(1, 53)]["value"] == 360.0
    assert results[(1, 54)]["value"] == 100.0


def test_subscribe_to(coap_controller):
    ids = (
        # On
        (1, 51),
        # Brightness
        (1, 52),
        # Hue
        (1, 53),
        # Saturation
        (1, 54),
    )
    pdu_results = [b""] * len(ids)

    results = coap_controller._subscribe_to_exit(ids, pdu_results)

    assert len(results) == 0


def test_subscribe_to_single_failure(coap_controller):
    ids = (
        # On
        (1, 51),
    )
    pdu_results = [PDUStatus.INVALID_REQUEST]

    results = coap_controller._subscribe_to_exit(ids, pdu_results)

    assert len(results) == 1
    assert isinstance(results[(1, 51)], dict)


def test_unsubscribe_from(coap_controller):
    ids = (
        # On
        (1, 51),
        # Brightness
        (1, 52),
        # Hue
        (1, 53),
        # Saturation
        (1, 54),
    )
    pdu_results = [b""] * len(ids)

    results = coap_controller._unsubscribe_from_exit(ids, pdu_results)

    assert len(results) == 0


def test_unsubscribe_from_single_failure(coap_controller):
    ids = (
        # On
        (1, 51),
    )
    pdu_results = [PDUStatus.INVALID_REQUEST]

    results = coap_controller._unsubscribe_from_exit(ids, pdu_results)

    assert len(results) == 1
    assert isinstance(results[(1, 51)], dict)
