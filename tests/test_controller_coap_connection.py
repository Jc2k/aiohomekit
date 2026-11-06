from unittest.mock import AsyncMock, MagicMock

from aiohomekit.controller.coap.connection import CoAPHomeKitConnection


def _connection() -> CoAPHomeKitConnection:
    return CoAPHomeKitConnection(None, "fd00::1", 5683)


async def test_reconnect_soon_shuts_down_the_session():
    connection = _connection()
    coap_ctx = MagicMock(shutdown=AsyncMock())
    connection.enc_ctx = MagicMock(coap_ctx=coap_ctx)

    await connection.reconnect_soon()

    coap_ctx.shutdown.assert_awaited_once()
    assert connection.enc_ctx is None


async def test_reconnect_soon_after_the_session_ended():
    """post_bytes() sets coap_ctx to None on a timeout but keeps enc_ctx."""
    connection = _connection()
    connection.enc_ctx = MagicMock(coap_ctx=None)

    await connection.reconnect_soon()

    assert connection.enc_ctx is None


async def test_reconnect_soon_without_a_session():
    connection = _connection()

    await connection.reconnect_soon()

    assert connection.enc_ctx is None
