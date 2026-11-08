import asyncio
import logging
import struct
from unittest.mock import AsyncMock, MagicMock

from aiocoap.error import LibraryShutdown
import pytest

from aiohomekit.characteristic_cache import CharacteristicCacheMemory
from aiohomekit.controller.coap.connection import CoAPHomeKitConnection
from aiohomekit.controller.coap.controller import CoAPController
from aiohomekit.controller.coap.pairing import CoAPPairing
from aiohomekit.controller.coap.pdu import OpCode
from aiohomekit.controller.coap.structs import (
    Pdu09Accessory,
    Pdu09AccessoryContainer,
    Pdu09Characteristic,
    Pdu09CharacteristicContainer,
    Pdu09Database,
    Pdu09Service,
    Pdu09ServiceContainer,
)
from aiohomekit.exceptions import AccessoryDisconnectedError, EncryptionError
from aiohomekit.model import Accessories, AccessoriesState, Categories
from aiohomekit.model.feature_flags import FeatureFlags
from aiohomekit.model.status_flags import StatusFlags
from aiohomekit.protocol.tlv import HAP_TLV, TLV
from aiohomekit.utils import _BACKGROUND_TASKS
from aiohomekit.zeroconf import HomeKitService

DEVICE_ID = "00:00:00:00:00:01"

NAME = (1, 2)
ON = (1, 51)
BRIGHTNESS = (1, 52)
BUTTON = (1, 60)

# properties: secure read, secure write, events
READ_WRITE_NOTIFY = 0x10 | 0x20 | 0x80
READ_NOTIFY = 0x10 | 0x80


def _characteristic(
    char_type: int, iid: int, properties: int, value_format: int
) -> Pdu09CharacteristicContainer:
    presentation_format = struct.pack("<BbHBH", value_format, 0, 0x2700, 1, 0)
    return Pdu09CharacteristicContainer(
        Pdu09Characteristic(char_type, iid, properties, presentation_format, None, None, None, None)
    )


def _service(service_type: int, iid: int, characteristics: list) -> Pdu09ServiceContainer:
    return Pdu09ServiceContainer(Pdu09Service(service_type, iid, characteristics, None, b""))


# A bulb with a button, as a CoAP accessory database.
DATABASE = Pdu09Database(
    [
        Pdu09AccessoryContainer(
            Pdu09Accessory(
                1,
                [
                    _service(0x3E, 1, [_characteristic(0x23, NAME[1], 0x10, 0x19)]),
                    _service(
                        0x43,
                        50,
                        [
                            _characteristic(0x25, ON[1], READ_WRITE_NOTIFY, 0x01),
                            _characteristic(0x08, BRIGHTNESS[1], READ_WRITE_NOTIFY, 0x10),
                        ],
                    ),
                    # stateless programmable switch with a ProgrammableSwitchEvent
                    _service(0x89, 59, [_characteristic(0x73, BUTTON[1], READ_NOTIFY, 0x04)]),
                ],
            )
        )
    ]
).encode()


class FakeSession:
    """Stands in for a pair-verified EncryptionContext and answers the accessory's reads."""

    def __init__(self, accessory: "FakeAccessory") -> None:
        self.accessory = accessory
        self.coap_ctx = MagicMock(shutdown=AsyncMock())

    async def post(self, opcode, iid, data):
        assert opcode == OpCode.UNK_09_READ_GATT
        self.accessory.requests += 1
        return 0, self.accessory.database

    async def post_all(self, opcode, iids, data):
        assert opcode == OpCode.CHAR_READ
        self.accessory.requests += 1
        self.accessory.reads += 1
        await self.accessory.reads_allowed.wait()
        return [
            bytes(TLV.encode_list([(HAP_TLV.kTLVHAPParamValue, self.accessory.values[iid])]))
            if iid in self.accessory.values
            else b""
            for iid in iids
        ]


class FakeAccessory:
    def __init__(self) -> None:
        self.database = DATABASE
        self.requests = 0
        self.reads = 0
        self.reads_allowed = asyncio.Event()
        self.reads_allowed.set()
        # the bulb was off before it lost power; the name reads back empty
        self.values = {ON[1]: b"\x00", BRIGHTNESS[1]: struct.pack("<l", 40), BUTTON[1]: b"\x00"}


def _description(state_num: int) -> HomeKitService:
    return HomeKitService(
        name="Test Bulb",
        id=DEVICE_ID,
        model="Test",
        feature_flags=FeatureFlags(0),
        status_flags=StatusFlags(0),
        config_num=1,
        state_num=state_num,
        category=Categories.LIGHTBULB,
        protocol_version="1.1",
        type="_hap._udp.local.",
        address="fd00::1",
        addresses=["fd00::1"],
        port=5683,
    )


async def _drain_background_tasks() -> None:
    if not _BACKGROUND_TASKS:
        return
    _, pending = await asyncio.wait(set(_BACKGROUND_TASKS), timeout=5)
    for task in pending:
        task.cancel()
    assert not pending, "background tasks still running"


def _lose_session(pairing: CoAPPairing) -> None:
    # what post_bytes() does when a request times out
    pairing.connection.enc_ctx.coap_ctx = None


@pytest.fixture
async def accessory():
    return FakeAccessory()


@pytest.fixture
async def pairing(mock_asynczeroconf, accessory: FakeAccessory, caplog):
    caplog.set_level(logging.ERROR)
    controller = CoAPController(char_cache=CharacteristicCacheMemory(), zeroconf_instance=mock_asynczeroconf)
    pairing = CoAPPairing(
        controller,
        {"AccessoryIP": "fd00::1", "AccessoryPort": 5683, "AccessoryPairingID": DEVICE_ID},
    )

    async def pair_verify(pairing_data):
        pairing.connection.enc_ctx = FakeSession(accessory)

    pairing.connection.do_pair_verify = AsyncMock(side_effect=pair_verify)

    # set up as Home Assistant does, then lose the session
    pairing._accessories_state = AccessoriesState(Accessories(), 1)
    pairing._async_description_update(_description(1))
    await _drain_background_tasks()
    await pairing.list_accessories_and_characteristics()
    _lose_session(pairing)

    pairing.connection.do_pair_verify.reset_mock()
    pairing.connection.subscribe_to = AsyncMock()
    pairing.availability = MagicMock()
    pairing.dispatcher_availability_changed(pairing.availability)
    pairing.events = MagicMock()
    pairing.dispatcher_connect(pairing.events)
    yield pairing

    await _drain_background_tasks()
    records = caplog.get_records("setup") + caplog.get_records("call")
    assert not [r for r in records if r.name == "aiohomekit.utils"], "a background task failed"


async def test_state_change_while_disconnected_reconnects(pairing: CoAPPairing):
    pairing._async_description_update(_description(2))
    await pairing._reconnect_task

    pairing.connection.do_pair_verify.assert_awaited_once()
    assert pairing.is_connected
    pairing.availability.assert_called_once_with(True)
    # nothing is subscribed, so there is nothing to catch up on
    pairing.events.assert_not_called()


async def test_reconnect_passes_on_values_read_while_connecting(
    pairing: CoAPPairing, accessory: FakeAccessory
):
    pairing.subscriptions.update({NAME, ON, BRIGHTNESS, BUTTON})
    # the bulb comes back on at full brightness when power returns
    accessory.values.update({ON[1]: b"\x01", BRIGHTNESS[1]: struct.pack("<l", 100)})
    accessory.reads = 0

    pairing._async_description_update(_description(2))
    await pairing._reconnect_task

    pairing.connection.subscribe_to.assert_awaited_once()
    pairing.availability.assert_called_once_with(True)
    # the button press is left out, as is the name, which read back empty
    pairing.events.assert_called_once_with({ON: {"value": True}, BRIGHTNESS: {"value": 100}})
    # connecting reads each of the 3 services once, and nothing more is asked
    assert accessory.reads == 3


async def test_state_change_while_connected_does_nothing(pairing: CoAPPairing, accessory: FakeAccessory):
    pairing.connection.enc_ctx = FakeSession(accessory)
    pairing.subscriptions.update({ON, BRIGHTNESS})

    pairing._async_description_update(_description(2))
    await _drain_background_tasks()

    assert pairing._reconnect_task is None
    pairing.connection.do_pair_verify.assert_not_called()
    pairing.connection.subscribe_to.assert_not_called()
    pairing.availability.assert_not_called()
    pairing.events.assert_not_called()


async def test_state_change_with_nobody_listening_does_nothing(pairing: CoAPPairing):
    # what is left when Home Assistant fails to set an accessory up: it closes the
    # pairing and later retries with a new one, so nothing listens to this one
    pairing.availability_listeners.clear()

    pairing._async_description_update(_description(2))
    await _drain_background_tasks()

    assert pairing._reconnect_task is None
    pairing.connection.do_pair_verify.assert_not_called()


async def test_unchanged_state_num_does_nothing(pairing: CoAPPairing):
    pairing._async_description_update(_description(1))
    await _drain_background_tasks()

    pairing.connection.do_pair_verify.assert_not_called()


async def test_first_description_does_not_reconnect(pairing: CoAPPairing):
    pairing.description = None
    # a first description also counts as an endpoint change, and reconnect_soon()
    # doesn't yet cope with a session that has already ended (see #619)
    pairing.connection.enc_ctx = None

    pairing._async_description_update(_description(2))
    await _drain_background_tasks()

    pairing.connection.do_pair_verify.assert_not_called()


async def test_burst_of_state_changes_reconnects_once(pairing: CoAPPairing, accessory: FakeAccessory):
    release = asyncio.Event()

    async def slow_pair_verify(pairing_data):
        await release.wait()
        pairing.connection.enc_ctx = FakeSession(accessory)

    pairing.connection.do_pair_verify.side_effect = slow_pair_verify

    pairing._async_description_update(_description(2))
    task = pairing._reconnect_task
    await asyncio.sleep(0)
    pairing._async_description_update(_description(3))
    pairing._async_description_update(_description(4))
    assert pairing._reconnect_task is task

    release.set()
    await task

    pairing.connection.do_pair_verify.assert_awaited_once()
    pairing.availability.assert_called_once_with(True)


async def test_failed_reconnect_is_retried_on_next_state_change(pairing: CoAPPairing):
    pairing.connection.do_pair_verify.side_effect = asyncio.TimeoutError

    pairing._async_description_update(_description(2))
    await pairing._reconnect_task

    assert not pairing.is_connected
    pairing.availability.assert_not_called()
    assert pairing.connection.do_pair_verify.await_count == 1

    pairing._async_description_update(_description(3))
    await pairing._reconnect_task

    assert pairing.connection.do_pair_verify.await_count == 2


async def test_reconnect_retries_after_joining_a_failed_attempt(
    pairing: CoAPPairing, accessory: FakeAccessory
):
    pairing.subscriptions.add(ON)
    accessory.values[ON[1]] = b"\x01"
    started = asyncio.Event()
    fail = asyncio.Event()
    attempts = 0

    async def pair_verify(pairing_data):
        nonlocal attempts
        attempts += 1
        if attempts == 1:
            # a poll's attempt that began while the bulb was still off
            started.set()
            await fail.wait()
            raise asyncio.TimeoutError
        pairing.connection.enc_ctx = FakeSession(accessory)

    pairing.connection.do_pair_verify.side_effect = pair_verify
    joined = asyncio.Event()
    wait = pairing.connection_lock.wait

    async def wait_and_record():
        joined.set()
        return await wait()

    pairing.connection_lock.wait = wait_and_record
    poll = asyncio.create_task(pairing.get_characteristics([ON]))
    await started.wait()

    pairing._async_description_update(_description(2))
    await joined.wait()
    fail.set()
    await pairing._reconnect_task

    with pytest.raises(AccessoryDisconnectedError):
        await poll
    assert attempts == 2
    assert pairing.is_connected
    pairing.events.assert_called_once_with({ON: {"value": True}})


async def test_joined_attempt_with_unreadable_database_passes_nothing_on(
    pairing: CoAPPairing, accessory: FakeAccessory
):
    pairing.subscriptions.add(ON)
    accessory.values[ON[1]] = b"\x01"
    accessory.database = b"\xff\xff"
    started = asyncio.Event()
    release = asyncio.Event()

    async def slow_pair_verify(pairing_data):
        started.set()
        await release.wait()
        pairing.connection.enc_ctx = FakeSession(accessory)

    pairing.connection.do_pair_verify.side_effect = slow_pair_verify
    poll = asyncio.create_task(pairing.get_characteristics([ON]))
    await started.wait()

    pairing._async_description_update(_description(2))
    await asyncio.sleep(0)
    release.set()
    with pytest.raises(AccessoryDisconnectedError):
        await poll
    await pairing._reconnect_task

    # the database left over from before the outage must not be passed on
    pairing.events.assert_not_called()
    # and the session, which never resubscribed, is ended
    assert not pairing.is_connected


async def test_reconnect_with_unreadable_database_ends_the_session(
    pairing: CoAPPairing, accessory: FakeAccessory
):
    pairing.subscriptions.add(ON)
    accessory.database = b"\xff\xff"

    pairing._async_description_update(_description(2))
    await pairing._reconnect_task

    assert not pairing.is_connected
    pairing.connection.subscribe_to.assert_not_called()
    pairing.availability.assert_not_called()
    pairing.events.assert_not_called()


async def test_poll_with_failed_resubscribe_ends_the_session(pairing: CoAPPairing):
    pairing.subscriptions.add(ON)
    pairing.connection.subscribe_to = AsyncMock(side_effect=AccessoryDisconnectedError("Request timeout"))

    with pytest.raises(AccessoryDisconnectedError):
        await pairing.get_characteristics([ON])

    assert not pairing.is_connected
    pairing.availability.assert_not_called()


async def test_request_joined_to_a_failed_attempt_does_not_use_the_session(
    pairing: CoAPPairing, accessory: FakeAccessory
):
    pairing.subscriptions.add(ON)
    started = asyncio.Event()
    release = asyncio.Event()

    async def slow_pair_verify(pairing_data):
        started.set()
        await release.wait()
        pairing.connection.enc_ctx = FakeSession(accessory)

    pairing.connection.do_pair_verify.side_effect = slow_pair_verify
    pairing.connection.subscribe_to = AsyncMock(side_effect=AccessoryDisconnectedError("Request timeout"))
    joined = asyncio.Event()
    wait = pairing.connection_lock.wait

    async def wait_and_record():
        joined.set()
        return await wait()

    pairing.connection_lock.wait = wait_and_record

    pairing._async_description_update(_description(2))
    await started.wait()
    poll = asyncio.create_task(pairing.get_characteristics([ON]))
    await joined.wait()
    release.set()
    await pairing._reconnect_task
    reads = accessory.reads

    with pytest.raises(AccessoryDisconnectedError):
        await poll
    assert accessory.reads == reads
    assert not pairing.is_connected


async def test_retry_is_decided_when_the_reconnect_is_scheduled(
    pairing: CoAPPairing, accessory: FakeAccessory
):
    attempts = 0

    async def pair_verify(pairing_data):
        nonlocal attempts
        attempts += 1
        if attempts == 1:
            raise asyncio.TimeoutError
        pairing.connection.enc_ctx = FakeSession(accessory)

    pairing.connection.do_pair_verify.side_effect = pair_verify

    # an attempt is in progress when the bulb advertises, and fails before the
    # reconnect starts, so the reconnect's own first attempt may also be too early
    pairing.connection_future = asyncio.get_running_loop().create_future()
    pairing._async_description_update(_description(2))
    pairing.connection_future = None
    await pairing._reconnect_task

    assert attempts == 2
    assert pairing.is_connected


@pytest.mark.parametrize(
    "error",
    [
        AccessoryDisconnectedError("Request timeout"),
        EncryptionError("Decryption failed"),
        LibraryShutdown(),
    ],
)
async def test_failed_resubscribe_ends_the_session(pairing: CoAPPairing, error: Exception):
    pairing.subscriptions.add(ON)
    pairing.connection.subscribe_to = AsyncMock(side_effect=error)

    pairing._async_description_update(_description(2))
    await pairing._reconnect_task

    assert pairing._reconnect_task.exception() is None
    assert not pairing.is_connected
    pairing.availability.assert_not_called()
    pairing.events.assert_not_called()


async def test_shutdown_before_reconnect_runs(pairing: CoAPPairing):
    pairing.subscriptions.add(ON)

    pairing._async_description_update(_description(2))
    await pairing.shutdown()

    assert pairing._reconnect_task.cancelled()
    pairing.connection.do_pair_verify.assert_not_called()
    pairing.availability.assert_not_called()
    pairing.events.assert_not_called()


async def test_shutdown_while_connecting_cancels_the_reconnect(pairing: CoAPPairing):
    pairing.subscriptions.add(ON)
    started = asyncio.Event()

    async def hanging_pair_verify(pairing_data):
        started.set()
        await asyncio.Event().wait()

    pairing.connection.do_pair_verify.side_effect = hanging_pair_verify

    pairing._async_description_update(_description(2))
    await started.wait()
    await pairing.shutdown()

    assert pairing._reconnect_task.cancelled()
    assert not pairing.is_connected
    pairing.availability.assert_not_called()
    pairing.events.assert_not_called()


async def test_shutdown_while_resubscribing_ends_the_session(pairing: CoAPPairing, accessory: FakeAccessory):
    pairing.subscriptions.add(ON)
    started = asyncio.Event()

    async def hanging_subscribe(ids):
        started.set()
        await asyncio.Event().wait()

    pairing.connection.subscribe_to = AsyncMock(side_effect=hanging_subscribe)

    pairing._async_description_update(_description(2))
    await started.wait()
    session = pairing.connection.enc_ctx
    requests = accessory.requests
    await pairing.shutdown()

    assert pairing._reconnect_task.cancelled()
    # the interrupted session is ended rather than used to unsubscribe
    session.coap_ctx.shutdown.assert_awaited_once()
    assert accessory.requests == requests
    assert not pairing.is_connected
    pairing.availability.assert_not_called()
    pairing.events.assert_not_called()


async def test_shutdown_while_reading_the_database_ends_the_session(
    pairing: CoAPPairing, accessory: FakeAccessory
):
    pairing.subscriptions.add(ON)
    accessory.reads = 0
    accessory.reads_allowed.clear()

    pairing._async_description_update(_description(2))
    while not accessory.reads:
        await asyncio.sleep(0)
    session = pairing.connection.enc_ctx
    requests = accessory.requests
    await pairing.shutdown()

    assert pairing._reconnect_task.cancelled()
    session.coap_ctx.shutdown.assert_awaited_once()
    assert accessory.requests == requests
    assert not pairing.is_connected
    pairing.availability.assert_not_called()
    pairing.events.assert_not_called()


async def test_cancelled_pair_verify_closes_its_socket(pairing: CoAPPairing, monkeypatch):
    coap_client = MagicMock(shutdown=AsyncMock())
    coap_client.request.return_value.response = asyncio.get_running_loop().create_future()
    monkeypatch.setattr(
        "aiohomekit.controller.coap.connection.Context.create_server_context",
        AsyncMock(return_value=coap_client),
    )

    def session_keys(pairing_data):
        yield [(1, b"\x01")], []

    monkeypatch.setattr("aiohomekit.controller.coap.connection.get_session_keys", session_keys)
    pairing.connection.do_pair_verify = CoAPHomeKitConnection.do_pair_verify.__get__(pairing.connection)

    pairing._async_description_update(_description(2))
    while not coap_client.request.called:
        await asyncio.sleep(0)
    await pairing.shutdown()

    assert pairing._reconnect_task.cancelled()
    coap_client.shutdown.assert_awaited_once()


async def test_poll_overlapping_shutdown_still_completes(pairing: CoAPPairing, accessory: FakeAccessory):
    started = asyncio.Event()
    release = asyncio.Event()

    async def slow_pair_verify(pairing_data):
        started.set()
        await release.wait()
        pairing.connection.enc_ctx = FakeSession(accessory)

    pairing.connection.do_pair_verify.side_effect = slow_pair_verify
    poll = asyncio.create_task(pairing.get_characteristics([ON]))
    await started.wait()
    await pairing.shutdown()
    release.set()

    assert await poll == {ON: {"value": False}}


def _record_joins(pairing: CoAPPairing) -> asyncio.Event:
    joined = asyncio.Event()
    wait = pairing.connection_lock.wait

    async def wait_and_record():
        joined.set()
        return await wait()

    pairing.connection_lock.wait = wait_and_record
    return joined


async def test_request_during_set_up_waits_for_it(pairing: CoAPPairing, accessory: FakeAccessory):
    pairing.subscriptions.add(ON)
    started = asyncio.Event()
    fail = asyncio.Event()

    async def failing_subscribe(ids):
        started.set()
        await fail.wait()
        raise AccessoryDisconnectedError("Request timeout")

    pairing.connection.subscribe_to = AsyncMock(side_effect=failing_subscribe)
    joined = _record_joins(pairing)

    pairing._async_description_update(_description(2))
    await started.wait()
    reads = accessory.reads
    # pair verify has succeeded, but the session isn't set up yet
    poll = asyncio.create_task(pairing.get_characteristics([ON]))
    await joined.wait()
    fail.set()
    await pairing._reconnect_task

    with pytest.raises(AccessoryDisconnectedError):
        await poll
    # the poll never used the session that was then ended
    assert accessory.reads == reads
    assert not pairing.is_connected


async def test_reconnect_joins_an_attempt_being_set_up_and_retries(
    pairing: CoAPPairing, accessory: FakeAccessory
):
    pairing.subscriptions.add(ON)
    accessory.values[ON[1]] = b"\x01"
    started = asyncio.Event()
    fail = asyncio.Event()
    subscribes = 0

    async def subscribe(ids):
        nonlocal subscribes
        subscribes += 1
        if subscribes == 1:
            started.set()
            await fail.wait()
            raise AccessoryDisconnectedError("Request timeout")

    pairing.connection.subscribe_to = AsyncMock(side_effect=subscribe)
    joined = _record_joins(pairing)
    # a poll has got past pair verify when the bulb advertises
    poll = asyncio.create_task(pairing.get_characteristics([ON]))
    await started.wait()

    pairing._async_description_update(_description(2))
    await joined.wait()
    fail.set()
    await pairing._reconnect_task

    with pytest.raises(AccessoryDisconnectedError):
        await poll
    assert pairing.connection.do_pair_verify.await_count == 2
    assert pairing.is_connected
    pairing.events.assert_called_once_with({ON: {"value": True}})


async def test_reconnect_joining_an_attempt_being_set_up_passes_on_its_values(
    pairing: CoAPPairing, accessory: FakeAccessory
):
    pairing.subscriptions.add(ON)
    accessory.values[ON[1]] = b"\x01"
    started = asyncio.Event()
    release = asyncio.Event()

    async def slow_subscribe(ids):
        started.set()
        await release.wait()

    pairing.connection.subscribe_to = AsyncMock(side_effect=slow_subscribe)
    joined = _record_joins(pairing)
    # a poll has read the accessory database and is resubscribing when the bulb
    # advertises
    poll = asyncio.create_task(pairing.get_characteristics([ON]))
    await started.wait()

    pairing._async_description_update(_description(2))
    await joined.wait()
    release.set()
    await poll
    await pairing._reconnect_task

    pairing.connection.do_pair_verify.assert_awaited_once()
    pairing.events.assert_called_once_with({ON: {"value": True}})
