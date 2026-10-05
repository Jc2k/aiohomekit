"""CoAP must not remain pinned to an unreachable advertised address."""

import asyncio
from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock, patch

import pytest
from aiocoap import Message
from aiocoap.error import NetworkError
from aiocoap.numbers.codes import Code

from aiohomekit.controller.coap.connection import CoAPHomeKitConnection
from aiohomekit.controller.coap.pairing import CoAPPairing
from aiohomekit.exceptions import AccessoryDisconnectedError, AuthenticationError

FIRST = "[2001:db8::1]:5683"
SECOND = "[2001:db8::2]:5683"


def make_pairing():
    controller = Mock()
    controller._char_cache.get_map.return_value = None
    pairing = CoAPPairing(
        controller,
        {"AccessoryPairingID": "00:00:00:00:00:01", "AccessoryIP": "2001:db8::1", "AccessoryPort": 5683},
    )
    pairing.description = SimpleNamespace(addresses=["2001:db8::1", "2001:db8::2"], port=5683, name="test")
    return pairing


@pytest.mark.parametrize("failure", [asyncio.TimeoutError(), NetworkError("unreachable")])
def test_pairing_tries_next_advertised_address(failure):
    """A failing first route must not hide a reachable second route."""

    async def scenario():
        pairing = make_pairing()
        connection = pairing.connection
        attempts = []

        async def verify(_data):
            attempts.append(connection.address)
            if connection.address == FIRST:
                raise failure
            connection.enc_ctx = SimpleNamespace(coap_ctx=object())

        connection.do_pair_verify = AsyncMock(side_effect=verify)
        connection.get_accessory_info = AsyncMock()
        connection.subscribe_to = AsyncMock()
        pairing.subscriptions = {(1, 51)}
        availability = Mock()
        pairing.availability_listeners.add(availability)

        await pairing._ensure_connected()

        assert attempts == [FIRST, SECOND]
        assert connection.address == SECOND
        assert pairing.is_connected
        connection.get_accessory_info.assert_awaited_once()
        connection.subscribe_to.assert_awaited_once_with([(1, 51)])
        availability.assert_called_once_with(True)
        assert pairing.connection_future is None

    asyncio.run(scenario())


def test_successful_address_is_reused_without_replaying_failed_route():
    async def scenario():
        pairing = make_pairing()
        pairing.connection.address = SECOND
        pairing.connection.do_pair_verify = AsyncMock()
        pairing.connection.get_accessory_info = AsyncMock()
        await pairing._ensure_connected()
        pairing.connection.do_pair_verify.assert_awaited_once()
        assert pairing.connection.address == SECOND

    asyncio.run(scenario())


def test_exhausted_addresses_are_bounded_and_retried_on_next_poll():
    async def scenario():
        pairing = make_pairing()
        attempts = []

        async def verify(_data):
            attempts.append(pairing.connection.address)
            raise asyncio.TimeoutError

        pairing.connection.do_pair_verify = AsyncMock(side_effect=verify)
        pairing.connection.get_accessory_info = AsyncMock()
        for _ in range(2):
            with pytest.raises(AccessoryDisconnectedError):
                await pairing._ensure_connected()
            assert pairing.connection_future is None

        assert len(attempts) == 4
        assert set(attempts[:2]) == {FIRST, SECOND}
        assert set(attempts[2:]) == {FIRST, SECOND}
        pairing.connection.get_accessory_info.assert_not_awaited()

    asyncio.run(scenario())


@pytest.mark.parametrize("failure", [AuthenticationError("rejected"), ValueError("malformed")])
def test_non_transport_failure_does_not_try_other_addresses(failure):
    async def scenario():
        pairing = make_pairing()
        pairing.connection.do_pair_verify = AsyncMock(side_effect=failure)
        with pytest.raises(AccessoryDisconnectedError):
            await pairing._ensure_connected()
        pairing.connection.do_pair_verify.assert_awaited_once()
        assert pairing.connection.address == FIRST

    asyncio.run(scenario())


def test_without_discovery_uses_saved_endpoint():
    async def scenario():
        pairing = make_pairing()
        pairing.description = None
        pairing.connection.do_pair_verify = AsyncMock()
        pairing.connection.get_accessory_info = AsyncMock()
        await pairing._ensure_connected()
        pairing.connection.do_pair_verify.assert_awaited_once()
        assert pairing.connection.address == FIRST

    asyncio.run(scenario())


def test_connected_session_is_not_replaced():
    async def scenario():
        pairing = make_pairing()
        pairing.connection.enc_ctx = SimpleNamespace(coap_ctx=object())
        pairing.connection.do_pair_verify = AsyncMock()
        await pairing._ensure_connected()
        pairing.connection.do_pair_verify.assert_not_awaited()

    asyncio.run(scenario())


def test_removed_endpoint_is_not_retried():
    async def scenario():
        pairing = make_pairing()
        pairing.description.addresses = ["2001:db8::2"]
        pairing.connection.do_pair_verify = AsyncMock()
        pairing.connection.get_accessory_info = AsyncMock()
        await pairing._ensure_connected()
        assert pairing.connection.address == SECOND

    asyncio.run(scenario())


def test_duplicate_addresses_are_attempted_once():
    async def scenario():
        pairing = make_pairing()
        pairing.description.addresses = ["2001:db8::1", "2001:db8::1"]
        pairing.connection.do_pair_verify = AsyncMock(side_effect=asyncio.TimeoutError)
        with pytest.raises(AccessoryDisconnectedError):
            await pairing._ensure_connected()
        pairing.connection.do_pair_verify.assert_awaited_once()

    asyncio.run(scenario())


def test_existing_connection_api_works_without_address_list():
    async def scenario():
        connection = CoAPHomeKitConnection(None, "2001:db8::1", 5683)
        connection.do_pair_verify = AsyncMock()
        connection.get_accessory_info = AsyncMock()
        await connection.connect({})
        connection.do_pair_verify.assert_awaited_once_with({})

    asyncio.run(scenario())


@pytest.mark.parametrize("failure", [asyncio.TimeoutError(), NetworkError("unreachable")])
def test_failed_pair_verify_context_is_closed_before_fallback(failure):
    """Exercise real pair verification, replacing only the network and keys."""

    async def scenario():
        pairing = make_pairing()
        pairing.connection.get_accessory_info = AsyncMock()
        clients = [Mock(shutdown=AsyncMock()), Mock(shutdown=AsyncMock())]
        for index, client in enumerate(clients):
            response = asyncio.get_running_loop().create_future()
            if index == 0:
                response.set_exception(failure)
            else:
                response.set_result(Message(code=Code.CHANGED, payload=b""))
            client.request.return_value = SimpleNamespace(response=response)

        def session_keys(_data):
            yield [], []
            return None, lambda _salt, _info: bytes(32)

        async def create_context(*_args, **_kwargs):
            if clients[0].request.called:
                clients[0].shutdown.assert_awaited_once()
                return clients[1]
            return clients[0]

        with (
            patch(
                "aiohomekit.controller.coap.connection.Context.create_server_context",
                side_effect=create_context,
            ),
            patch("aiohomekit.controller.coap.connection.get_session_keys", side_effect=session_keys),
        ):
            await pairing._ensure_connected()

        assert pairing.is_connected
        assert pairing.connection.enc_ctx.coap_ctx is clients[1]
        assert pairing.connection.enc_ctx.uri == f"coap://{SECOND}/"
        clients[0].shutdown.assert_awaited_once()
        clients[1].shutdown.assert_not_awaited()
        assert clients[0].request.call_args.args[0].get_request_uri() == f"coap://{FIRST}/2"
        assert clients[1].request.call_args.args[0].get_request_uri() == f"coap://{SECOND}/2"

    asyncio.run(scenario())


def test_concurrent_callers_share_failover_sequence():
    async def scenario():
        pairing = make_pairing()
        entered = asyncio.Event()
        release = asyncio.Event()
        attempts = []

        async def verify(_data):
            attempts.append(pairing.connection.address)
            if pairing.connection.address == FIRST:
                entered.set()
                await release.wait()
                raise asyncio.TimeoutError
            pairing.connection.enc_ctx = SimpleNamespace(coap_ctx=object())

        pairing.connection.do_pair_verify = AsyncMock(side_effect=verify)
        pairing.connection.get_accessory_info = AsyncMock()
        first = asyncio.create_task(pairing._ensure_connected())
        await entered.wait()
        second = asyncio.create_task(pairing._ensure_connected())
        await asyncio.sleep(0)
        release.set()
        await asyncio.gather(first, second)
        assert attempts == [FIRST, SECOND]
        pairing.connection.get_accessory_info.assert_awaited_once()

    asyncio.run(scenario())


def test_failed_characteristic_write_is_not_replayed():
    async def scenario():
        pairing = make_pairing()
        pairing.connection.enc_ctx = SimpleNamespace(coap_ctx=object())
        pairing.connection.do_pair_verify = AsyncMock()
        pairing.connection.write_characteristics = AsyncMock(
            side_effect=AccessoryDisconnectedError("Request timeout")
        )
        with pytest.raises(AccessoryDisconnectedError):
            await pairing.put_characteristics([(1, 51, True)])
        pairing.connection.write_characteristics.assert_awaited_once_with([(1, 51, True)])
        pairing.connection.do_pair_verify.assert_not_awaited()

    asyncio.run(scenario())
