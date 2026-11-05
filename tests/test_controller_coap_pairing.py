import asyncio
import socket
import struct
import sys

from aiocoap import Context, Message, resource
from aiocoap.numbers.codes import Code
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
import pytest

from aiohomekit.characteristic_cache import CharacteristicCacheMemory
from aiohomekit.controller.coap.connection import EncryptionContext
from aiohomekit.controller.coap.controller import CoAPController
from aiohomekit.controller.coap.pairing import CoAPPairing
from aiohomekit.controller.coap.pdu import OpCode
from aiohomekit.controller.coap.structs import Pdu09Database
from aiohomekit.model import Categories
from aiohomekit.model.feature_flags import FeatureFlags
from aiohomekit.model.status_flags import StatusFlags
from aiohomekit.utils import _BACKGROUND_TASKS
from aiohomekit.zeroconf import HomeKitService

from tests.test_controller_coap import database_nanoleaf_bulb

# Mirror aiocoap's default UDP transport selection.
CLIENT_TRANSPORTS = ["udp6"] if sys.platform == "linux" else ["simple6"]
SERVER_TRANSPORTS = ["udp6"] if sys.platform == "linux" else ["simplesocketserver"]

CONTROLLER_TO_ACCESSORY_KEY = bytes(range(32))
ACCESSORY_TO_CONTROLLER_KEY = bytes(reversed(range(32)))
DEVICE_ID = "00:00:00:00:00:01"
ACCESSORY_NAME = "Test Bulb"


def _description(address: str, port: int, config_num: int) -> HomeKitService:
    return HomeKitService(
        name="Test Bulb",
        id=DEVICE_ID,
        model="Test",
        feature_flags=FeatureFlags(0),
        status_flags=StatusFlags(0),
        config_num=config_num,
        state_num=1,
        category=Categories.LIGHTBULB,
        protocol_version="1.1",
        type="_hap._udp.local.",
        address=address,
        addresses=[address],
        port=port,
    )


def _pairing(controller: CoAPController, address: str, port: int) -> CoAPPairing:
    return CoAPPairing(
        controller,
        {
            "AccessoryIP": address,
            "AccessoryPort": port,
            "AccessoryPairingID": DEVICE_ID,
        },
    )


def _new_background_tasks(before: set[asyncio.Task]) -> list[asyncio.Task]:
    return list(_BACKGROUND_TASKS - before)


def _free_udp_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


@pytest.fixture
async def coap_controller(mock_asynczeroconf):
    return CoAPController(char_cache=CharacteristicCacheMemory(), zeroconf_instance=mock_asynczeroconf)


@pytest.mark.parametrize(
    ("old_address", "old_port", "new_address", "new_port", "reconnects"),
    [
        ("::1", 12345, "::1", 12345, False),
        ("::1", 12345, "0:0:0:0:0:0:0:1", 12345, False),
        ("127.0.0.1", 12345, "127.0.0.1", 12345, False),
        ("::1", 12345, "::1", 12346, True),
        ("127.0.0.1", 12345, "127.0.0.2", 12345, True),
        ("::1%1", 12345, "::1%2", 12345, True),
    ],
)
async def test_first_description_reconnects_only_for_changed_endpoint(
    coap_controller: CoAPController,
    old_address: str,
    old_port: int,
    new_address: str,
    new_port: int,
    reconnects: bool,
):
    pairing = _pairing(coap_controller, old_address, old_port)
    coap_ctx = await Context.create_client_context(transports=CLIENT_TRANSPORTS)
    enc_ctx = EncryptionContext(None, None, None, "coap://[::1]:9/", coap_ctx)
    pairing.connection.enc_ctx = enc_ctx
    address_before = pairing.connection.address

    try:
        # config_num -1 keeps this test about the endpoint; no refresh is scheduled.
        before = set(_BACKGROUND_TASKS)
        pairing._async_description_update(_description(new_address, new_port, -1))
        tasks = _new_background_tasks(before)
        await asyncio.gather(*tasks)

        assert bool(tasks) is reconnects
        if reconnects:
            assert pairing.connection.enc_ctx is None
            assert pairing.connection.address != address_before
            assert pairing.connection.address.endswith(f"]:{new_port}")
        else:
            assert pairing.connection.enc_ctx is enc_ctx
            assert pairing.connection.address == address_before

        # The same advertisement seen again never reconnects.
        before = set(_BACKGROUND_TASKS)
        pairing._async_description_update(_description(new_address, new_port, -1))
        assert not _new_background_tasks(before)
    finally:
        if pairing.connection.enc_ctx is enc_ctx:
            await coap_ctx.shutdown()


class GatedAccessory(resource.Resource):
    """Answer encrypted HAP PDUs; hold the first database read until released."""

    def __init__(self) -> None:
        super().__init__()
        self.database_read_started = asyncio.Event()
        self.release_database_read = asyncio.Event()
        self.database_reads = 0
        self._recv_ctr = 0
        self._send_ctr = 0
        self._database = Pdu09Database.decode(database_nanoleaf_bulb)

    def _value(self, iid: int) -> bytes:
        characteristic = self._database.find_characteristic_by_iid(iid)
        if characteristic.data_type_str == "string":
            characteristic.value = ACCESSORY_NAME
        elif characteristic.data_type_str == "data":
            characteristic.value = ""
        else:
            characteristic.value = 0
        value = characteristic.raw_value
        return bytes([1, len(value)]) + value

    async def render_post(self, request):
        nonce = struct.pack("=4xQ", self._recv_ctr)
        payload = ChaCha20Poly1305(CONTROLLER_TO_ACCESSORY_KEY).decrypt(nonce, request.payload, b"")
        self._recv_ctr += 1

        response = bytearray()
        offset = 0
        while offset < len(payload):
            _, opcode, tid, iid, length = struct.unpack_from("<BBBHH", payload, offset)
            offset += 7 + length
            if opcode == OpCode.UNK_09_READ_GATT.value:
                self.database_reads += 1
                body = database_nanoleaf_bulb
                if self.database_reads == 1:
                    self.database_read_started.set()
                    await self.release_database_read.wait()
            else:
                assert opcode == OpCode.CHAR_READ.value
                body = self._value(iid)
            response += struct.pack("<BBBH", 0b0000_0010, tid, 0, len(body)) + body

        nonce = struct.pack("=4xQ", self._send_ctr)
        self._send_ctr += 1
        return Message(
            code=Code.CHANGED,
            payload=ChaCha20Poly1305(ACCESSORY_TO_CONTROLLER_KEY).encrypt(nonce, bytes(response), b""),
        )


async def test_first_same_endpoint_description_does_not_interrupt_initial_read(
    coap_controller: CoAPController,
):
    port = _free_udp_port()
    accessory = GatedAccessory()
    site = resource.Site()
    site.add_resource([], accessory)
    server = await Context.create_server_context(site, bind=("127.0.0.1", port), transports=SERVER_TRANSPORTS)
    client = await Context.create_client_context(transports=CLIENT_TRANSPORTS)

    pairing = _pairing(coap_controller, "127.0.0.1", port)
    # Session state as left by pair verify.
    pairing.connection.enc_ctx = EncryptionContext(
        ChaCha20Poly1305(ACCESSORY_TO_CONTROLLER_KEY),
        ChaCha20Poly1305(CONTROLLER_TO_ACCESSORY_KEY),
        ChaCha20Poly1305(bytes(32)),
        f"coap://127.0.0.1:{port}/",
        client,
    )

    primary_name = asyncio.create_task(pairing.get_primary_name())
    background: list[asyncio.Task] = []
    try:
        await accessory.database_read_started.wait()
        assert pairing.description is None

        # First advertisement after pairing: same endpoint, newer config number.
        before = set(_BACKGROUND_TASKS)
        pairing._async_description_update(_description("127.0.0.1", port, 2))
        background = _new_background_tasks(before)
        # Let the scheduled tasks start before the in-flight read completes.
        await asyncio.sleep(0)
        accessory.release_database_read.set()

        assert await primary_name == ACCESSORY_NAME
        await asyncio.gather(*background)
        assert pairing.connection.is_connected
        assert pairing.config_num == 2
        assert coap_controller._char_cache.get_map(DEVICE_ID)["config_num"] == 2
        assert accessory.database_reads == 2
    finally:
        accessory.release_database_read.set()
        primary_name.cancel()
        # Let any reconnect finish its own shutdown rather than cancelling it midway.
        await asyncio.gather(primary_name, *background, return_exceptions=True)
        if pairing.connection.enc_ctx is not None:
            await client.shutdown()
        await server.shutdown()
