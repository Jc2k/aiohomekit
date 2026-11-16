"""A handshake can retain its selected endpoint despite a discovery update."""

import asyncio
from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock, patch

import pytest
from aiocoap import Message
from aiocoap.numbers.codes import Code

from aiohomekit.controller.coap.pairing import CoAPPairing

FIRST = "[2001:db8::1]:5683"
UPDATED = "[2001:db8::2]:5683"


@pytest.mark.parametrize("update_discovery", [False, True])
def test_handshake_retains_selected_endpoint(update_discovery):
    """Check endpoint consistency, not accessory support for session migration."""

    async def scenario():
        controller = Mock()
        controller._char_cache.get_map.return_value = None
        pairing = CoAPPairing(
            controller,
            {"AccessoryPairingID": "00:00:00:00:00:01", "AccessoryIP": "2001:db8::1", "AccessoryPort": 5683},
        )
        pairing.description = SimpleNamespace(
            address="2001:db8::1", addresses=["2001:db8::1"], port=5683, name="test"
        )
        pairing.connection.get_accessory_info = AsyncMock()
        client = Mock(shutdown=AsyncMock())
        response = asyncio.get_running_loop().create_future()
        entered = asyncio.Event()
        client.request.return_value = SimpleNamespace(response=response)

        def session_keys(_data):
            yield [], []
            return None, lambda _salt, _info: bytes(32)

        async def create_context(*_args, **_kwargs):
            entered.set()
            return client

        with (
            patch(
                "aiohomekit.controller.coap.connection.Context.create_server_context",
                side_effect=create_context,
            ) as create_client,
            patch("aiohomekit.controller.coap.connection.get_session_keys", side_effect=session_keys),
        ):
            connecting = asyncio.create_task(pairing._ensure_connected())
            await asyncio.wait_for(entered.wait(), 1)
            if update_discovery:
                pairing.description = SimpleNamespace(
                    address="2001:db8::2", addresses=["2001:db8::2"], port=5683, name="test"
                )
                pairing._async_endpoint_changed()
                await asyncio.sleep(0)
            response.set_result(Message(code=Code.CHANGED, payload=b""))
            await asyncio.wait_for(connecting, 1)

        create_client.assert_awaited_once()
        client.request.assert_called_once()
        client.shutdown.assert_not_awaited()
        assert pairing.connection.address == (UPDATED if update_discovery else FIRST)
        assert client.request.call_args.args[0].get_request_uri() == f"coap://{FIRST}/2"
        assert pairing.connection.enc_ctx.uri == f"coap://{FIRST}/"
        pairing.connection.get_accessory_info.assert_awaited_once()

    asyncio.run(scenario())
