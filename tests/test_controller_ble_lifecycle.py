"""BLE lifecycle ordering with real client methods and in-memory transport."""

import asyncio
import sys
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest

if sys.platform != "linux":
    pytest.skip("BlueZ lifecycle tests require Linux", allow_module_level=True)
from bleak.backends.characteristic import BleakGATTCharacteristic
from bleak.backends.device import BLEDevice
from bleak.backends.service import BleakGATTService, BleakGATTServiceCollection
from dbus_fast import Message
from dbus_fast.constants import MessageType

from aiohomekit.characteristic_cache import CharacteristicCacheMemory
from aiohomekit.controller.ble import pairing as module
from aiohomekit.controller.ble.bleak import AIOHomeKitBleakClient, BleakServiceMissing
from aiohomekit.controller.ble.controller import BleController
from aiohomekit.exceptions import AccessoryDisconnectedError
from aiohomekit.model import Accessory, Accessories, AccessoriesState
from aiohomekit.model.characteristics import CharacteristicsTypes
from aiohomekit.model.services import ServicesTypes
from aiohomekit.controller.ble.key import DecryptionKey, EncryptionKey
from aiohomekit.pdu import OpCode
from aiohomekit.protocol.tlv import TLV


class MemoryBus:
    """Actual dbus-fast messages, zero real D-Bus connections."""

    def __init__(self, client, value):
        self.client = client
        self.value = value
        self.closed = False
        self.close_calls = 0
        self.tid = None
        self.read_started = asyncio.Event()
        self.read_reply = asyncio.Event()
        self.read_reply.set()
        self.write_started = asyncio.Event()
        self.write_reply = asyncio.Event()
        self.write_reply.set()
        self.close_started = asyncio.Event()
        self.close_reply = asyncio.Event()
        self.close_reply.set()
        self.close_error = None
        self.disconnect_call_error = None
        self.write_decoder = None
        self.read_encoder = None

    @property
    def connected(self):
        return not self.closed

    async def call(self, message):
        if message.member == "Disconnect":
            if self.disconnect_call_error:
                raise self.disconnect_call_error
            remote_disconnect(self.client)
            return Message(message_type=MessageType.METHOD_RETURN, reply_serial=1)
        if message.member == "WriteValue":
            data = bytes(message.body[0])
            if self.write_decoder:
                data = self.write_decoder.decrypt(data)
            self.tid = data[2]
            self.write_started.set()
            await self.write_reply.wait()
            if self.closed:
                raise EOFError("simulated close before write reply")
            return Message(message_type=MessageType.METHOD_RETURN, reply_serial=1)
        assert message.member == "ReadValue"
        self.read_started.set()
        await self.read_reply.wait()
        if self.closed:
            raise EOFError("simulated close before read reply")
        assert self.tid is not None
        # Real HomeKit response PDU, consumed by aiohomekit.client._read_pdu.
        payload = bytes((2, self.tid, 0)) + len(self.value).to_bytes(2, "little") + self.value
        if self.read_encoder:
            payload = self.read_encoder.encrypt(payload)
        return Message(message_type=MessageType.METHOD_RETURN, reply_serial=1, signature="ay", body=[payload])

    def disconnect(self):
        self.close_calls += 1
        self.closed = True
        self.close_started.set()

    async def wait_for_disconnect(self):
        await self.close_reply.wait()
        if self.close_error:
            raise self.close_error


def remote_disconnect(client):
    backend = client._backend
    backend._is_connected = False
    backend._cleanup_all()
    if backend._disconnected_callback:
        backend._disconnected_callback()
    if backend._disconnecting_event:
        backend._disconnecting_event.set()


def attach_client(pairing):
    client = AIOHomeKitBleakClient("AA:BB:CC:DD:EE:FF", disconnected_callback=pairing._async_disconnected)
    backend = client._backend
    assert type(backend).__name__ == "BleakClientBlueZDBus"
    path = "/org/bluez/hci0/dev_AA_BB_CC_DD_EE_FF/service0001/char0002"
    service = BleakGATTService(obj=None, handle=1, uuid=ServicesTypes.LIGHTBULB)
    characteristic = BleakGATTCharacteristic(
        obj=(path, {}),
        handle=2,
        uuid=CharacteristicsTypes.ON,
        properties=["read", "write"],
        max_write_without_response_size=lambda: 20,
        service=service,
    )
    collection = BleakGATTServiceCollection()
    collection.add_service(service)
    collection.add_characteristic(characteristic)
    backend.services = collection
    backend._is_connected = True
    backend._device_path = "/org/bluez/hci0/dev_AA_BB_CC_DD_EE_FF"
    backend._remove_device_watcher = lambda: None
    value = TLV.encode_list([(1, b"\x01")])
    bus = MemoryBus(client, value)
    backend._bus = bus
    client.test_bus = bus
    return client


@pytest.fixture
def pairing():
    controller = BleController(CharacteristicCacheMemory())
    instance = module.BlePairing(
        controller,
        {
            "AccessoryPairingID": "aa:bb:cc:dd:ee:ff",
            "AccessoryAddress": "AA:BB:CC:DD:EE:FF",
            "Connection": "BLE",
        },
        device=BLEDevice("AA:BB:CC:DD:EE:FF", "synthetic", {}),
    )
    accessories = Accessories()
    accessory = Accessory.create_with_info(1, "synthetic", "synthetic", "synthetic", "0", "0")
    accessories.add_accessory(accessory)
    service = accessory.add_service(ServicesTypes.LIGHTBULB)
    characteristic = service.add_char(CharacteristicsTypes.ON)
    instance._accessories_state = AccessoriesState(accessories, 1, None)
    instance.test_char = characteristic
    instance.client = attach_client(instance)
    return instance


async def request(pairing):
    return await pairing._async_request(OpCode.CHAR_READ, pairing.test_char)


async def ensure(pairing):
    async with pairing._client_lock, pairing._config_lock:
        return await pairing._ensure_connected()


@pytest.mark.asyncio
async def test_real_homekit_pdu_uses_official_bleak_api(pairing):
    payload = await request(pairing)
    assert dict(TLV.decode_bytes(payload))[1] == b"\x01"
    await pairing.close()


@pytest.mark.asyncio
async def test_real_package_close_waits_for_pdu_response(pairing):
    bus = pairing.client.test_bus
    bus.read_reply.clear()
    operation = asyncio.create_task(request(pairing))
    await asyncio.wait_for(bus.read_started.wait(), 1)
    close = asyncio.create_task(pairing.close())
    await asyncio.sleep(0)
    assert not bus.closed
    bus.read_reply.set()
    payload = await operation
    assert dict(TLV.decode_bytes(payload))[1] == b"\x01"
    await close
    assert pairing.client is None
    assert bus.close_calls == 1


@pytest.mark.asyncio
async def test_real_package_close_waits_for_write_reply(pairing):
    bus = pairing.client.test_bus
    bus.write_reply.clear()
    operation = asyncio.create_task(request(pairing))
    await asyncio.wait_for(bus.write_started.wait(), 1)
    close = asyncio.create_task(pairing.close())
    await asyncio.sleep(0)
    assert not bus.closed
    bus.write_reply.set()
    await operation
    await close
    assert bus.closed


@pytest.mark.asyncio
async def test_real_package_remote_disconnect_then_reconnect(pairing, monkeypatch):
    old = pairing.client
    bus = old.test_bus
    bus.read_reply.clear()
    operation = asyncio.create_task(request(pairing))
    await asyncio.wait_for(bus.read_started.wait(), 1)
    remote_disconnect(old)
    created = []

    async def establish(*args, **kwargs):
        new = attach_client(pairing)
        created.append(new)
        return new

    monkeypatch.setattr(module, "establish_connection", establish)
    reconnect = asyncio.create_task(ensure(pairing))
    await asyncio.sleep(0)
    assert not bus.closed and not created
    bus.read_reply.set()
    with pytest.raises(AccessoryDisconnectedError):
        await operation
    await reconnect
    assert bus.closed
    assert pairing.client is created[0]
    assert not pairing.client.test_bus.closed
    await pairing.close()


@pytest.mark.asyncio
async def test_real_package_cancelled_pdu_cleanup(pairing):
    old = pairing.client
    old.test_bus.read_reply.clear()
    operation = asyncio.create_task(request(pairing))
    await asyncio.wait_for(old.test_bus.read_started.wait(), 1)
    operation.cancel()
    with pytest.raises(asyncio.CancelledError):
        await operation
    assert pairing.client is None
    assert old.test_bus.closed
    assert not pairing._client_lock._lock.locked()


@pytest.mark.asyncio
async def test_shutdown_waits_for_pending_read_then_closes(pairing):
    old = pairing.client
    old.test_bus.read_reply.clear()
    operation = asyncio.create_task(request(pairing))
    await asyncio.wait_for(old.test_bus.read_started.wait(), 1)
    shutdown = asyncio.create_task(pairing.shutdown())
    await asyncio.sleep(0.03)
    assert not shutdown.done()
    assert pairing.client is old and not old.test_bus.closed
    old.test_bus.read_reply.set()
    await asyncio.wait_for(operation, 1)
    await asyncio.wait_for(shutdown, 1)
    assert pairing._shutdown and pairing.client is None
    assert old.test_bus.closed


@pytest.mark.asyncio
async def test_expected_disconnect_error_uses_no_cleanup_registry(pairing):
    old = pairing.client
    old.test_bus.close_error = EOFError("simulated incomplete Bleak cleanup")
    await pairing.close()
    assert pairing.client is None
    # No retry/queue is implemented here: cleanup on an error belongs to Bleak.


@pytest.mark.asyncio
async def test_real_package_late_callback_ignores_new_client(pairing):
    old = pairing.client
    await pairing.close()
    new = attach_client(pairing)
    pairing.client = new
    key = object()
    pairing._encryption_key = key
    pairing._async_disconnected(old)
    assert pairing._encryption_key is key
    assert pairing.client is new
    await pairing.close()


@pytest.mark.asyncio
async def test_real_package_two_concurrent_closes(pairing):
    old = pairing.client
    await asyncio.gather(pairing.close(), pairing.close())
    assert old.test_bus.close_calls == 1
    assert pairing.client is None


@pytest.mark.asyncio
async def test_real_package_public_operation_restores_and_resumes(pairing, monkeypatch):
    populate = AsyncMock()
    restore = AsyncMock()
    monkeypatch.setattr(pairing, "_populate_accessories_and_characteristics", populate)
    monkeypatch.setattr(pairing, "_async_restore_subscriptions", restore)
    pairing._restore_pending = True
    result = await pairing.get_characteristics([(1, pairing.test_char.iid)])
    assert result == {(1, pairing.test_char.iid): {"value": True}}
    populate.assert_awaited_once()
    restore.assert_awaited_once()
    await pairing.close()


def encrypted_session(pairing):
    write_key, read_key = b"\x11" * 32, b"\x22" * 32
    pairing._encryption_key = EncryptionKey(write_key)
    pairing._decryption_key = DecryptionKey(read_key)
    pairing.client.test_bus.write_decoder = DecryptionKey(write_key)
    pairing.client.test_bus.read_encoder = EncryptionKey(read_key)


@pytest.mark.asyncio
async def test_real_package_encrypted_pdu_counters_survive_successive_requests(pairing):
    encrypted_session(pairing)
    for _ in range(2):
        payload = await request(pairing)
        assert dict(TLV.decode_bytes(payload))[1] == b"\x01"
    await pairing.close()


@pytest.mark.asyncio
async def test_real_package_close_waits_for_encrypted_response(pairing):
    encrypted_session(pairing)
    bus = pairing.client.test_bus
    bus.read_reply.clear()
    operation = asyncio.create_task(request(pairing))
    await asyncio.wait_for(bus.read_started.wait(), 1)
    close = asyncio.create_task(pairing.close())
    await asyncio.sleep(0)
    assert not bus.closed
    bus.read_reply.set()
    payload = await operation
    assert dict(TLV.decode_bytes(payload))[1] == b"\x01"
    await close
    assert pairing._encryption_key is None


@pytest.mark.asyncio
async def test_real_package_second_cancellation_during_cleanup_retains_client(pairing):
    old = pairing.client
    old.test_bus.read_reply.clear()
    old.test_bus.close_reply.clear()
    operation = asyncio.create_task(request(pairing))
    await asyncio.wait_for(old.test_bus.read_started.wait(), 1)
    operation.cancel()
    await asyncio.wait_for(old.test_bus.close_started.wait(), 1)
    operation.cancel()
    with pytest.raises(asyncio.CancelledError):
        await operation
    assert pairing.client is old
    assert not pairing._client_lock._lock.locked()
    old.test_bus.close_reply.set()
    await pairing.close()
    assert pairing.client is None


def capture_notification_tasks(monkeypatch):
    tasks = []

    def spawn(coroutine):
        task = asyncio.create_task(coroutine)
        tasks.append(task)
        return task

    monkeypatch.setattr(module, "async_create_task", spawn)
    return tasks


async def subscribe(pairing):
    async with pairing._client_lock, pairing._operation_lock:
        await pairing._async_start_notify(pairing.test_char.iid)
    return pairing.client.start_notify.await_args.args[1]


@pytest.mark.asyncio
async def test_late_notification_cannot_schedule_work_for_new_client(pairing, monkeypatch):
    old = pairing.client
    old.start_notify = AsyncMock()
    callback = await subscribe(pairing)
    await pairing.close()
    new = attach_client(pairing)
    pairing.client = new
    tasks = capture_notification_tasks(monkeypatch)
    callback(pairing.test_char.iid, b"")
    assert not tasks
    assert new.test_bus.tid is None
    await pairing.close()


@pytest.mark.asyncio
async def test_queued_notification_rechecks_identity_after_waiting(pairing, monkeypatch):
    old = pairing.client
    old.start_notify = AsyncMock()
    callback = await subscribe(pairing)
    tasks = capture_notification_tasks(monkeypatch)
    async with pairing._client_lock, pairing._operation_lock:
        callback(pairing.test_char.iid, b"")
        await asyncio.sleep(0)
        assert len(tasks) == 1 and not tasks[0].done()
        await pairing.close()
        new = attach_client(pairing)
        pairing.client = new
    await asyncio.wait_for(tasks[0], 1)
    assert new.test_bus.tid is None
    assert not pairing._had_notify_this_session
    await pairing.close()


@pytest.mark.asyncio
async def test_current_notification_still_reads_characteristic(pairing, monkeypatch):
    client = pairing.client
    client.start_notify = AsyncMock()
    pairing.description = SimpleNamespace(name="synthetic", state_num=1, config_num=1)
    tasks = capture_notification_tasks(monkeypatch)
    callback = await subscribe(pairing)
    callback(pairing.test_char.iid, b"")
    await asyncio.wait_for(tasks[0], 1)
    assert client.test_bus.tid is not None
    assert pairing._had_notify_this_session
    assert pairing.description.state_num == 2
    await pairing.close()


@pytest.mark.asyncio
async def test_subscription_setup_finishes_before_close(pairing):
    old = pairing.client
    started, reply = asyncio.Event(), asyncio.Event()

    async def start_notify(*args):
        started.set()
        await reply.wait()

    old.start_notify = AsyncMock(side_effect=start_notify)
    operation = asyncio.create_task(subscribe(pairing))
    await asyncio.wait_for(started.wait(), 1)
    close = asyncio.create_task(pairing.close())
    await asyncio.sleep(0)
    assert not old.test_bus.closed
    reply.set()
    await operation
    await close
    assert old.test_bus.closed
    assert not pairing._notifications


@pytest.mark.asyncio
async def test_disconnect_during_endpoint_lookup_sends_no_new_pdu(pairing, monkeypatch):
    old = pairing.client
    endpoint = await old.get_characteristic(pairing.test_char.service.type, pairing.test_char.type)
    started, reply = asyncio.Event(), asyncio.Event()

    async def lookup(*args):
        started.set()
        await reply.wait()
        return endpoint

    old.get_characteristic = AsyncMock(side_effect=lookup)
    pdu = AsyncMock()
    monkeypatch.setattr(module, "ble_request", pdu)
    operation = asyncio.create_task(request(pairing))
    await asyncio.wait_for(started.wait(), 1)
    remote_disconnect(old)
    reply.set()
    with pytest.raises(AccessoryDisconnectedError):
        await operation
    pdu.assert_not_awaited()
    await pairing.close()


@pytest.mark.asyncio
async def test_old_success_response_cannot_be_used_for_replacement_client(pairing, monkeypatch):
    new = attach_client(pairing)
    old = pairing.client

    async def old_response(*args):
        pairing.client = new
        return module.PDUStatus.SUCCESS, b"old response"

    monkeypatch.setattr(module, "ble_request", old_response)
    with pytest.raises(AccessoryDisconnectedError):
        await request(pairing)
    assert pairing.client is new
    assert not new.test_bus.closed
    await pairing.close()
    await old.disconnect()


@pytest.mark.asyncio
async def test_current_disconnect_callback_still_resets_keys(pairing):
    key = object()
    pairing._encryption_key = pairing._decryption_key = key
    pairing._async_disconnected(pairing.client)
    assert pairing._encryption_key is None
    assert pairing._decryption_key is None
    await pairing.close()


@pytest.mark.asyncio
async def test_missing_service_uses_public_close_and_clears_active_client(pairing):
    old = pairing.client
    old.clear_cache = AsyncMock()

    async def missing(self):
        raise BleakServiceMissing("synthetic missing service")

    handler = module.disconnect_on_missing_services(missing)
    with pytest.raises(BleakServiceMissing):
        await handler(pairing)
    old.clear_cache.assert_awaited_once()
    assert old.test_bus.close_calls == 1
    assert pairing.client is None


@pytest.mark.asyncio
async def test_cache_error_still_requests_public_close(pairing):
    old = pairing.client
    old.clear_cache = AsyncMock(side_effect=RuntimeError("synthetic cache failure"))

    async def missing(self):
        raise BleakServiceMissing("synthetic missing service")

    handler = module.disconnect_on_missing_services(missing)
    with pytest.raises(RuntimeError, match="cache failure"):
        await handler(pairing)
    assert old.test_bus.close_calls == 1
    assert pairing.client is None


@pytest.mark.asyncio
async def test_disconnect_during_notify_endpoint_lookup_starts_no_subscription(pairing):
    old = pairing.client
    endpoint = await old.get_characteristic(pairing.test_char.service.type, pairing.test_char.type)
    started, reply = asyncio.Event(), asyncio.Event()

    async def lookup(*args):
        started.set()
        await reply.wait()
        return endpoint

    old.get_characteristic = AsyncMock(side_effect=lookup)
    old.start_notify = AsyncMock()
    operation = asyncio.create_task(subscribe(pairing))
    await asyncio.wait_for(started.wait(), 1)
    remote_disconnect(old)
    reply.set()
    with pytest.raises(AccessoryDisconnectedError):
        await operation
    old.start_notify.assert_not_awaited()
    await pairing.close()


@pytest.mark.asyncio
async def test_discovery_missing_gatt_keeps_direct_disconnect():
    from aiohomekit.controller.ble.client import disconnect_on_missing_services

    client = SimpleNamespace(clear_cache=AsyncMock(), disconnect=AsyncMock())
    discovery = SimpleNamespace(client=client, name="synthetic")

    async def missing(self):
        raise BleakServiceMissing("synthetic missing service")

    with pytest.raises(BleakServiceMissing):
        await disconnect_on_missing_services(missing)(discovery)
    client.clear_cache.assert_awaited_once()
    client.disconnect.assert_awaited_once()


@pytest.mark.asyncio
async def test_discovery_cache_error_preserves_existing_behavior():
    from aiohomekit.controller.ble.client import disconnect_on_missing_services

    client = SimpleNamespace(
        clear_cache=AsyncMock(side_effect=RuntimeError("synthetic cache failure")),
        disconnect=AsyncMock(),
    )
    discovery = SimpleNamespace(client=client, name="synthetic")

    async def missing(self):
        raise BleakServiceMissing("synthetic missing service")

    with pytest.raises(RuntimeError, match="cache failure"):
        await disconnect_on_missing_services(missing)(discovery)
    client.clear_cache.assert_awaited_once()
    client.disconnect.assert_not_awaited()


@pytest.mark.asyncio
async def test_disconnect_during_establish_rejects_request_then_reconnects(pairing, monkeypatch):
    old = pairing.client
    remote_disconnect(old)
    created = []

    async def establish(*args, **kwargs):
        new = attach_client(pairing)
        created.append(new)
        if len(created) == 1:
            # Fire the real backend callback before establish returns the client.
            remote_disconnect(new)
        return new

    monkeypatch.setattr(module, "establish_connection", establish)
    async with pairing._config_lock:
        await pairing._ensure_connected()
    disconnected = created[0]
    assert old.test_bus.closed
    assert pairing.client is disconnected
    assert not disconnected.is_connected
    with pytest.raises(AccessoryDisconnectedError):
        await request(pairing)
    assert disconnected.test_bus.tid is None

    async with pairing._config_lock:
        await pairing._ensure_connected()
    assert disconnected.test_bus.closed
    assert pairing.client is created[1]
    assert pairing.client.is_connected
    await request(pairing)
    pairing._async_disconnected(disconnected)
    assert pairing.client is created[1]
    assert pairing.client.is_connected
    await pairing.close()
    assert pairing.client is None
    assert created[1].test_bus.closed
