import asyncio
from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock

import pytest
from aiocoap import Message
from aiocoap.numbers.codes import Code

from aiohomekit.controller.coap.connection import CoAPHomeKitConnection, EncryptionContext
from aiohomekit.controller.coap.pdu import OpCode, PDUStatus
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


def test_write_characteristics(coap_controller: CoAPHomeKitConnection):
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
    assert tlv_values[2] == b"\x01\x04\x00\x00\xb4\x43"
    assert tlv_values[3] == b"\x01\x04\x00\x00\xc8\x42"

    results = coap_controller._write_characteristics_exit(values, [b""] * len(values))

    assert len(results) == 0


def test_read_characteristics(coap_controller: CoAPHomeKitConnection):
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
        b"\x01\x04\x00\x00\xb4\x43",
        b"\x01\x04\x00\x00\xc8\x42",
    ]

    results = coap_controller._read_characteristics_exit(ids, pdu_results)

    assert len(results) == 4
    assert results[(1, 51)]["value"] is True
    assert results[(1, 52)]["value"] == 100
    assert results[(1, 53)]["value"] == 360.0
    assert results[(1, 54)]["value"] == 100.0


def test_subscribe_to(coap_controller: CoAPHomeKitConnection):
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


def test_subscribe_to_single_failure(coap_controller: CoAPHomeKitConnection):
    ids = (
        # On
        (1, 51),
    )
    pdu_results = [PDUStatus.INVALID_REQUEST]

    results = coap_controller._subscribe_to_exit(ids, pdu_results)

    assert len(results) == 1
    assert isinstance(results[(1, 51)], dict)


def test_unsubscribe_from(coap_controller: CoAPHomeKitConnection):
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


def test_unsubscribe_from_single_failure(coap_controller: CoAPHomeKitConnection):
    ids = (
        # On
        (1, 51),
    )
    pdu_results = [PDUStatus.INVALID_REQUEST]

    results = coap_controller._unsubscribe_from_exit(ids, pdu_results)

    assert len(results) == 1
    assert isinstance(results[(1, 51)], dict)


@pytest.fixture
def coap_transport(coap_controller):
    """Use the real request/session locking with a mocked CoAP transport."""
    transport = Mock()
    context = EncryptionContext(None, None, None, "coap://[::1]/0", transport)
    context.encrypt = Mock(side_effect=lambda payload: payload)
    context._decrypt_response = AsyncMock(side_effect=lambda response: response.payload)
    coap_controller.enc_ctx = context

    def respond(payload=b"\x02\x00\x00\x00\x00"):
        future = asyncio.get_running_loop().create_future()
        future.set_result(Message(code=Code.CHANGED, payload=payload))
        return SimpleNamespace(response=future)

    transport.request.side_effect = lambda request: respond()
    transport.respond = respond
    return transport


def require_timed_write(controller, iid=51):
    """Mark a synthetic fixture characteristic as requiring timed writes."""
    controller.info.find_characteristic_by_aid_iid(1, iid).properties |= 0x0008


@pytest.mark.parametrize("value", [False, True])
async def test_timed_write_wire_format(coap_controller, coap_transport, value):
    """A tw characteristic uses a length-prefixed value/TTL then an empty execute."""
    require_timed_write(coap_controller)

    assert await coap_controller.write_characteristics([(1, 51, value)]) == {}

    requests = [args.args[0].payload for args in coap_transport.request.call_args_list]
    assert requests == [
        b"\x00\x04\x00\x33\x00\x08\x00\x06\x00\x01\x01" + bytes([value]) + b"\x08\x01\x1e",
        b"\x00\x05\x00\x33\x00\x00\x00",
    ]


async def test_normal_writes_still_batched(coap_controller, coap_transport):
    """Characteristics without tw retain a single ordinary batch request."""
    coap_transport.request.side_effect = lambda request: coap_transport.respond(
        b"\x02\x00\x00\x00\x00\x02\x01\x00\x00\x00"
    )

    assert await coap_controller.write_characteristics([(1, 51, True), (1, 52, 100)]) == {}

    coap_transport.request.assert_called_once()
    assert coap_transport.request.call_args.args[0].payload == (
        b"\x00\x02\x00\x33\x00\x03\x00\x01\x01\x01\x00\x02\x01\x34\x00\x06\x00\x01\x04\x64\x00\x00\x00"
    )


async def test_mixed_writes_preserve_order(coap_controller, coap_transport):
    """Flush ordinary writes before each timed prepare/execute pair."""
    require_timed_write(coap_controller, 52)

    assert await coap_controller.write_characteristics([(1, 51, True), (1, 52, 100), (1, 53, 360.0)]) == {}

    requests = [args.args[0].payload for args in coap_transport.request.call_args_list]
    assert [(p[1], int.from_bytes(p[3:5], "little")) for p in requests] == [
        (OpCode.CHAR_WRITE.value, 51),
        (OpCode.CHAR_TIMED_WRITE.value, 52),
        (OpCode.CHAR_EXEC_WRITE.value, 52),
        (OpCode.CHAR_WRITE.value, 53),
    ]
    assert requests[1][7:] == b"\x09\x00\x01\x04\x64\x00\x00\x00\x08\x01\x1e"


@pytest.mark.parametrize("failed_step", [0, 1])
async def test_timed_write_rejection(coap_controller, coap_transport, failed_step):
    """Report either phase's failure and never execute a rejected prepare."""
    require_timed_write(coap_controller)
    replies = [b"\x02\x00\x00\x00\x00"] * failed_step + [b"\x02\x00\x06\x00\x00"]
    coap_transport.request.side_effect = lambda request: coap_transport.respond(replies.pop(0))

    result = await coap_controller.write_characteristics([(1, 51, True)])

    assert result[(1, 51)]["status"] == -PDUStatus.INVALID_REQUEST.value
    assert coap_transport.request.call_count == failed_step + 1


async def test_rejected_timed_write_continues_batch(coap_controller, coap_transport):
    """A rejected prepare still allows later ordinary writes in the batch."""
    require_timed_write(coap_controller)
    replies = [b"\x02\x00\x06\x00\x00", b"\x02\x00\x00\x00\x00"]
    coap_transport.request.side_effect = lambda request: coap_transport.respond(replies.pop(0))

    result = await coap_controller.write_characteristics([(1, 51, True), (1, 52, 100)])

    assert list(result) == [(1, 51)]
    assert result[(1, 51)]["status"] == -PDUStatus.INVALID_REQUEST.value
    assert [args.args[0].payload[1] for args in coap_transport.request.call_args_list] == [4, 2]


@pytest.mark.parametrize("concurrent_operation", ["read", "write", "timed_write"])
async def test_timed_write_not_interleaved(coap_controller, coap_transport, concurrent_operation):
    """A queued request cannot run between prepare and execute on the session."""
    require_timed_write(coap_controller)
    if concurrent_operation == "timed_write":
        require_timed_write(coap_controller, 52)
    prepare_pending = asyncio.get_running_loop().create_future()
    request_started = asyncio.Event()

    def respond(request):
        if coap_transport.request.call_count == 1:
            request_started.set()
            return SimpleNamespace(response=prepare_pending)
        return coap_transport.respond()

    coap_transport.request.side_effect = respond
    first = asyncio.create_task(coap_controller.write_characteristics([(1, 51, True)]))
    await asyncio.wait_for(request_started.wait(), timeout=1)
    if concurrent_operation == "read":
        operation = coap_controller.read_characteristics([(1, 52)])
    else:
        operation = coap_controller.write_characteristics([(1, 52, 100)])
    second = asyncio.create_task(operation)
    # Let the competing request queue on the session lock before prepare completes.
    await asyncio.sleep(0)
    prepare_pending.set_result(Message(code=Code.CHANGED, payload=b"\x02\x00\x00\x00\x00"))
    await asyncio.wait_for(asyncio.gather(first, second), timeout=1)

    opcodes = [args.args[0].payload[1] for args in coap_transport.request.call_args_list]
    expected_tail = {"read": [3], "write": [2], "timed_write": [4, 5]}
    assert opcodes == [4, 5, *expected_tail[concurrent_operation]]


async def test_cancelled_timed_write_releases_session_lock(coap_controller, coap_transport):
    """Cancelling prepare releases the lock and does not send execute."""
    require_timed_write(coap_controller)
    prepare_pending = asyncio.get_running_loop().create_future()
    request_started = asyncio.Event()

    def respond(request):
        request_started.set()
        return SimpleNamespace(response=prepare_pending)

    coap_transport.request.side_effect = respond
    task = asyncio.create_task(coap_controller.write_characteristics([(1, 51, True)]))
    await asyncio.wait_for(request_started.wait(), timeout=1)
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task

    assert not coap_controller.enc_ctx.lock.locked()
    coap_transport.request.assert_called_once()
    coap_transport.request.side_effect = lambda request: coap_transport.respond()
    assert await coap_controller.write_characteristics([(1, 52, 100)]) == {}


async def test_empty_write_sends_no_request(coap_controller, coap_transport):
    """An empty write list does not send an empty PDU batch."""
    assert await coap_controller.write_characteristics([]) == {}
    coap_transport.request.assert_not_called()
