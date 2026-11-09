"""Queued requests should report a closed CoAP session, not dereference None."""

import asyncio
from unittest.mock import AsyncMock, Mock

import pytest
from aiocoap import Message
from aiocoap.error import NetworkError
from aiocoap.numbers.codes import Code

from aiohomekit.controller.coap.connection import EncryptionContext
from aiohomekit.exceptions import AccessoryDisconnectedError


@pytest.mark.parametrize("failure", [asyncio.TimeoutError(), NetworkError("unreachable")])
def test_queued_request_after_transport_failure(failure):
    async def scenario():
        response = asyncio.get_running_loop().create_future()
        client = Mock(shutdown=AsyncMock())
        client.request.return_value.response = response
        send = Mock()
        send.encrypt.return_value = b"encrypted"
        context = EncryptionContext(Mock(), send, Mock(), "coap://[2001:db8::1]:5683/", client)

        first = asyncio.create_task(context.post_bytes(b"first"))
        await asyncio.sleep(0)
        assert client.request.call_count == 1
        second = asyncio.create_task(context.post_bytes(b"second"))
        await asyncio.sleep(0)
        response.set_exception(failure)
        results = await asyncio.gather(first, second, return_exceptions=True)

        assert all(isinstance(result, AccessoryDisconnectedError) for result in results)
        client.request.assert_called_once()
        client.shutdown.assert_awaited_once()
        send.encrypt.assert_called_once()
        assert context.coap_ctx is None
        assert context.send_ctr == 1

    asyncio.run(scenario())


def test_already_closed_session_does_not_encrypt_or_send():
    async def scenario():
        send = Mock()
        context = EncryptionContext(Mock(), send, Mock(), "coap://[2001:db8::1]:5683/", None)
        with pytest.raises(AccessoryDisconnectedError):
            await context.post_bytes(b"request")
        send.encrypt.assert_not_called()
        assert context.send_ctr == 0

    asyncio.run(scenario())


def test_healthy_request_is_unchanged():
    async def scenario():
        response = asyncio.get_running_loop().create_future()
        response.set_result(Message(code=Code.CHANGED, payload=b"encrypted reply"))
        client = Mock(shutdown=AsyncMock())
        client.request.return_value.response = response
        send = Mock()
        send.encrypt.return_value = b"encrypted request"
        context = EncryptionContext(Mock(), send, Mock(), "coap://[2001:db8::1]:5683/", client)
        context._decrypt_response = AsyncMock(return_value=b"reply")

        assert await context.post_bytes(b"request") == b"reply"
        client.request.assert_called_once()
        client.shutdown.assert_not_awaited()
        assert context.send_ctr == 1

    asyncio.run(scenario())
