#
# Copyright 2019 aiohomekit team
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
from __future__ import annotations

import asyncio
import logging
from typing import TYPE_CHECKING, Any

from async_interrupt import interrupt

from aiohomekit.crypto.chacha20poly1305 import (
    PACK_NONCE,
    ChaCha20Poly1305Decryptor,
    ChaCha20Poly1305Encryptor,
    DecryptionError,
)
from aiohomekit.exceptions import (
    AccessoryDisconnectedError,
    AccessoryNotFoundError,
    AuthenticationError,
    ConnectionError,
    HomeKitException,
    HttpErrorResponse,
    TimeoutError,
)
import aiohomekit.hkjson as hkjson
from aiohomekit.http import HttpContentTypes
from aiohomekit.http.response import HttpResponse
from aiohomekit.protocol import get_session_keys
from aiohomekit.protocol.tlv import TLV
from aiohomekit.utils import async_create_task, asyncio_timeout

if TYPE_CHECKING:
    from .pairing import IpPairing

logger = logging.getLogger(__name__)


class ConnectionReady(Exception):
    """Raised when a connection is ready to be retried."""


class InsecureHomeKitProtocol(asyncio.Protocol):
    """An asyncio.Protocol implementation for HomeKit connections."""

    def __init__(self, connection: HomeKitConnection) -> None:
        self.connection = connection
        self.host = ":".join((connection.host, str(connection.port)))
        self.result_cbs: list[asyncio.Future[HttpResponse]] = []
        self.current_response = HttpResponse()
        self.loop = asyncio.get_running_loop()

    def connection_made(self, transport):
        super().connection_made(transport)
        self.transport = transport

    def connection_lost(self, exception):
        self.connection._connection_lost(exception)

    def _handle_timeout(self, fut: asyncio.Future[Any]) -> None:
        """Handle a timeout."""
        if not fut.done():
            fut.set_exception(asyncio.TimeoutError)

    async def send_bytes(self, payload: bytes) -> HttpResponse:
        """Send bytes to the device."""
        if self.transport.is_closing():
            # FIXME: It would be nice to try and wait for the reconnect in future.
            # In that case we need to make sure we do it at a layer above send_bytes otherwise
            # we might encrypt payloads with the last sessions keys then wait for a new connection
            # to send them - and on that connection the keys would be different.
            # Also need to make sure that the new connection has chance to pair-verify before
            # queued writes can happy.
            raise AccessoryDisconnectedError("Transport is closed")

        self.transport.write(payload)

        # We return a future so that our caller can block on a reply
        # We can send many requests and dispatch the results in order
        # Should mean we don't need locking around request/reply cycles
        loop = self.loop
        result: asyncio.Future[HttpResponse] = loop.create_future()
        self.result_cbs.append(result)
        timeout_handle = loop.call_at(loop.time() + 30, self._handle_timeout, result)
        timeout_expired = False
        try:
            return await result
        except asyncio.TimeoutError:
            timeout_expired = True
            self.transport.write_eof()
            self.transport.close()
            raise AccessoryDisconnectedError("Timeout while waiting for response")
        finally:
            if not timeout_expired:
                timeout_handle.cancel()

    def data_received(self, data):
        while data:
            data = self.current_response.parse(data)

            if self.current_response.is_read_completely():
                http_name = self.current_response.get_http_name().lower()
                if http_name == "http":
                    next_callback = self.result_cbs.pop(0)
                    if not next_callback.done():
                        next_callback.set_result(self.current_response)
                elif http_name == "event":
                    self.connection.event_received(self.current_response)
                else:
                    raise RuntimeError("Unknown http type")

                self.current_response = HttpResponse()

    def eof_received(self):
        self.close()
        return False

    def close(self):
        # If the connection is closed then any pending callbacks will never
        # fire, so set them to an error state.
        while self.result_cbs:
            result = self.result_cbs.pop(0)
            result.set_exception(AccessoryDisconnectedError("Connection closed"))


class SecureHomeKitProtocol(InsecureHomeKitProtocol):
    """An asyncio.Protocol implementation for secure HomeKit connections."""

    def __init__(
        self, connection: HomeKitConnection, a2c_key: bytes, c2a_key: bytes
    ) -> None:
        super().__init__(connection)

        self._incoming_buffer: bytearray = bytearray()

        self.c2a_counter = 0
        self.a2c_counter = 0

        self.a2c_key = a2c_key
        self.c2a_key = c2a_key

        self.encryptor = ChaCha20Poly1305Encryptor(self.c2a_key)
        self.decryptor = ChaCha20Poly1305Decryptor(self.a2c_key)

    async def send_bytes(self, payload: bytes) -> HttpResponse:
        buffer: list[bytes] = []

        while len(payload) > 0:
            current = payload[:1024]
            payload = payload[1024:]
            len_bytes = len(current).to_bytes(2, byteorder="little")
            buffer.append(len_bytes)
            buffer.append(
                self.encryptor.encrypt(
                    len_bytes,
                    PACK_NONCE(self.c2a_counter),
                    bytes(current),
                )
            )
            self.c2a_counter += 1

        return await super().send_bytes(b"".join(buffer))

    def data_received(self, data: bytes) -> None:
        """
        Called by asyncio when data is received from a TCP socket.

        This just handles decryption of 1024 blocks and its them over to the underlying
        InsecureHomeKitProtocol to handle HTTP unframing.

        The blocks are expected to be in order - there is no protocol level support for
        interleaving of HTTP messages.
        """

        self._incoming_buffer += data

        while len(self._incoming_buffer) >= 2:
            block_length_bytes = self._incoming_buffer[:2]
            block_length = int.from_bytes(block_length_bytes, "little")
            exp_length = block_length + 18

            if len(self._incoming_buffer) < exp_length:
                # Not enough data yet
                return

            # Drop the length from the top of the buffer as we have already parsed it
            del self._incoming_buffer[:2]

            block_and_tag = self._incoming_buffer[: block_length + 16]
            del self._incoming_buffer[: block_length + 16]

            try:
                decrypted = self.decryptor.decrypt(
                    bytes(block_length_bytes),
                    PACK_NONCE(self.a2c_counter),
                    bytes(block_and_tag),
                )
            except DecryptionError as err:
                raise RuntimeError("Could not decrypt block") from err

            self.a2c_counter += 1

            super().data_received(decrypted)


class HomeKitConnection:
    def __init__(
        self, owner: IpPairing, host: str, port: int, concurrency_limit: int = 1
    ) -> None:
        self.owner = owner
        self.host = host
        self.port = port

        self.closing: bool = False
        self.closed: bool = False
        self._retry_interval = 0.5

        self.transport: asyncio.Transport | None = None
        self.protocol: InsecureHomeKitProtocol | SecureHomeKitProtocol | None = None

        self._connector: asyncio.Task[None] | None = None

        self.is_secure: bool | None = False

        self._connect_lock = asyncio.Lock()

        self._loop = asyncio.get_running_loop()
        self._concurrency_limit = asyncio.Semaphore(concurrency_limit)
        self._reconnect_future: asyncio.Future[None] | None = None
        self._last_connector_error: Exception | None = None

    @property
    def name(self) -> str:
        """Return the name of the connection."""
        if self.owner:
            return self.owner.name
        return f"{self.host}:{self.port}"

    @property
    def is_connected(self) -> bool:
        """Return if the connection is active."""
        return self.transport and self.protocol and not self.closed

    def _start_connector(self) -> None:
        """
        Start a reconnect background task.

        This function is *not* thread safe. It should only be called on the main thread
        where the event loop is running. If it is not there is a race where multiple
        reconnect tasks could run at once.

        This function **will not** start another reconnect thread if one is already
        running. Or if it is already connected.
        """
        if (self._connector and not self._connector.done()) or self.is_connected:
            return
        self._connector = async_create_task(self._reconnect())

    def reconnect_soon(self) -> None:
        """Reconnect to the device if disconnected.

        If a reconnect is in progress, the reconnection wait is canceled
        and the reconnect proceeds.

        If a reconnect is not a progress, the connect loop is started.
        """
        if self._reconnect_future and not self._reconnect_future.done():
            # If a reconnect wait is running, cancel it so the reconnect
            # tries right away
            self._reconnect_future.set_result(None)
            return
        self._start_reconnecting()

    def _start_reconnecting(self) -> bool:
        """Start reconnecting."""
        if self.is_connected:
            return False
        self.closing = False
        self._start_connector()
        return True

    @property
    def last_connector_error(self) -> Exception | None:
        """Return the last error from the connector task."""
        return self._last_connector_error

    async def ensure_connection(self) -> None:
        """
        Waits for a connection to the device.

        If connected and authenticated returns immediately.

        Otherwise, if a reconnection is in progress wait for it to complete.

        Otherwise, start a reconnection and wait for it.
        """
        if self._start_reconnecting():
            # If we are running under a timeout, we still need to shield the
            # connector task so it continues to run if the timeout is hit.
            await asyncio.shield(self._connector)

    async def _stop_connector(self) -> None:
        """
        Cancels any active reconnect tasks.

        If no active reconnect tasks it will return immediately.

        Otherwise it will wait for the task to end.
        """
        if not self._connector:
            return
        self._connector.cancel("Stop connector")
        # Wait for the connector but do not propagate the CancelledError
        # since the connector will be canceled when the connection is closed.
        #
        # Cancellation of the connector will still happen but we won't
        # propagate it higher in the stack.
        try:
            await self._connector
        except asyncio.CancelledError:
            pass

    async def get(self, target: str) -> HttpResponse:
        """
        Sends a HTTP POST request to the current transport and returns an awaitable
        that can be used to wait for a response.
        """
        return await self.request(
            method="GET",
            target=target,
        )

    async def get_json(self, target: str) -> dict[str, Any]:
        response = await self.get(target)
        return hkjson.loads(response.body)

    async def put(
        self, target: str, body: bytes, content_type=HttpContentTypes.JSON
    ) -> HttpResponse:
        """
        Sends a HTTP POST request to the current transport and returns an awaitable
        that can be used to wait for a response.
        """
        return await self.request(
            method="PUT",
            target=target,
            headers=[
                ("Content-Length", len(body)),
                ("Content-Type", content_type.value),
            ],
            body=body,
        )

    async def put_json(self, target: str, body: Any) -> dict[str, Any]:
        response = await self.put(
            target,
            hkjson.dump_bytes(body),
            content_type=HttpContentTypes.JSON,
        )

        if response.code == 204:
            return {}

        try:
            decoded = response.body.decode("utf-8")
        except UnicodeDecodeError:
            self.transport.close()
            raise AccessoryDisconnectedError(
                "Session closed after receiving non-utf8 response"
            )

        try:
            parsed = hkjson.loads(decoded)
        except hkjson.JSON_DECODE_EXCEPTIONS:
            self.transport.close()
            raise AccessoryDisconnectedError(
                "Session closed after receiving malformed response from device"
            )

        return parsed

    async def post(
        self, target: str, body: bytes, content_type=HttpContentTypes.TLV
    ) -> HttpResponse:
        """
        Sends a HTTP POST request to the current transport and returns an awaitable
        that can be used to wait for a response.
        """
        return await self.request(
            method="POST",
            target=target,
            headers=[
                ("Content-Length", len(body)),
                ("Content-Type", content_type.value),
            ],
            body=body,
        )

    async def post_json(self, target: str, body: Any) -> dict[str, Any]:
        response = await self.post(
            target,
            hkjson.dump_bytes(body),
            content_type=HttpContentTypes.JSON,
        )

        if response.code != 204:
            # FIXME: ...
            pass

        decoded = response.body.decode("utf-8")

        if not decoded:
            # FIXME: Verify this is correct
            return {}

        try:
            parsed = hkjson.loads(decoded)
        except hkjson.JSON_DECODE_EXCEPTIONS:
            self.transport.close()
            raise AccessoryDisconnectedError(
                "Session closed after receiving malformed response from device"
            )

        return parsed

    async def post_tlv(self, target: str, body: list, expected=None) -> list:
        try:
            response = await self.post(
                target,
                TLV.encode_list(body),
                content_type=HttpContentTypes.TLV,
            )
        except HttpErrorResponse as e:
            self.transport.close()
            response = e.response
        body = TLV.decode_bytes(response.body, expected=expected)
        return body

    async def request(
        self,
        method: str,
        target: str,
        headers: list[tuple[str, str]] | None = None,
        body: bytes | None = None,
    ) -> HttpResponse:
        """
        Sends a HTTP request to the current transport and returns an awaitable
        that can be used to wait for the response.

        This will automatically set the header.

        :param method: A HTTP method, like 'GET' or 'POST'
        :param target: A URI to call the method on
        :param headers: a list of (header, value) tuples (optional)
        :param body: The body of the request (optional)
        """
        if not self.protocol:
            raise AccessoryDisconnectedError(
                "Connection lost before request could be sent"
            )

        buffer = []
        buffer.append(f"{method.upper()} {target} HTTP/1.1")

        # WARNING: It is vital that a Host: header is present or some devices
        # will reject the request.
        buffer.append(f"Host: {self.host}")

        if headers:
            for header, value in headers:
                buffer.append(f"{header}: {value}")

        buffer.append("")
        buffer.append("")

        # WARNING: We use \r\n explicitly. \n is not enough for some.
        request_bytes = "\r\n".join(buffer).encode("utf-8")

        if body:
            request_bytes += body

        # WARNING: It is vital that each request is sent in one call
        # Some devices are sensitive to unecrypted HTTP requests made in
        # multiple packets.

        # https://github.com/jlusiardi/homekit_python/issues/12
        # https://github.com/jlusiardi/homekit_python/issues/16

        async with self._concurrency_limit:
            if not self.protocol:
                raise AccessoryDisconnectedError("Tried to send while not connected")
            logger.debug("%s: raw request: %r", self.host, request_bytes)
            resp = await self.protocol.send_bytes(request_bytes)

        if resp.code >= 400 and resp.code <= 499:
            logger.debug(f"Got HTTP error {resp.code} for {method} against {target}")
            raise HttpErrorResponse(
                f"Got HTTP error {resp.code} for {method} against {target}",
                response=resp,
            )

        logger.debug("%s: raw response: %r", self.host, resp.body)

        return resp

    async def close(self) -> None:
        """
        Close the connection transport.
        """
        self.closing = True

        await self._stop_connector()

        if self.transport:
            self.transport.close()

        self.protocol = None
        self.transport = None
        self.is_secure = None

    def _connection_lost(self, exception: Exception) -> None:
        """
        Called by a Protocol instance when eof_received happens.
        """
        logger.debug("Connection %r lost.", self)

        if not self.closing:
            self._start_connector()

        if self.closing:
            self.closed = True

        self.transport = None
        self.protocol = None

    async def _connect_once(self) -> None:
        """_connect_once must only ever be called from _reconnect to ensure its done with a lock."""
        loop = asyncio.get_event_loop()

        logger.debug("Attempting connection to %s:%s", self.host, self.port)

        try:
            async with asyncio_timeout(10):
                self.transport, self.protocol = await loop.create_connection(
                    lambda: InsecureHomeKitProtocol(self), self.host, self.port
                )

        except asyncio.TimeoutError:
            raise TimeoutError("Timeout")

        except OSError as e:
            raise ConnectionError(str(e))

        if self.owner:
            await self.owner.connection_made(False)

    async def _reconnect(self) -> None:
        # When the device is seen by zeroconf, call reconnect_soon
        # to force the reconnect wait to be canceled and _connect_once
        # will be called soon.
        #
        # If an active service browser is running the entry that zeroconf
        # saw will already be in the cache and will be available to
        # _connect_once without having to do I/O
        #
        if self._connect_lock.locked():
            # Reconnect already in progress.
            return
        async with self._connect_lock:
            interval = 0.5

            logger.debug("Starting reconnect loop to %s:%s", self.host, self.port)

            while not self.closing:
                self._last_connector_error = None
                try:
                    return await self._connect_once()

                except AuthenticationError as ex:
                    self._last_connector_error = ex
                    # Authentication errors should bubble up because auto-reconnect is unlikely to help
                    raise

                except HomeKitException as ex:
                    self._last_connector_error = ex
                    logger.debug(
                        "%s: Connecting to accessory failed: %s; Retrying in %i seconds",
                        self.name,
                        ex,
                        interval,
                    )

                except Exception as ex:
                    self._last_connector_error = ex
                    logger.exception(
                        "%s: Unexpected error whilst trying to connect to accessory. Will retry.",
                        self.name,
                    )

                interval = min(60, 1.5 * interval)
                self._reconnect_future = self._loop.create_future()
                try:
                    async with interrupt(self._reconnect_future, ConnectionReady, None):
                        await asyncio.sleep(interval)
                except ConnectionReady:
                    pass
                finally:
                    self._reconnect_future = None

    def event_received(self, event: HttpResponse) -> None:
        if not self.owner:
            return

        # FIXME: Should drop the connection if can't parse the event?

        decoded = event.body.decode("utf-8")
        if not decoded:
            return

        try:
            parsed = hkjson.loads(decoded)
        except hkjson.JSON_DECODE_EXCEPTIONS:
            return

        self.owner.event_received(parsed)

    def __repr__(self) -> str:
        return f"HomeKitConnection(host={self.host!r}, port={self.port!r})"


class SecureHomeKitConnection(HomeKitConnection):
    """A HomeKit connection that negotiates a secure session."""

    def __init__(self, owner: IpPairing, pairing_data: dict[str, Any]) -> None:
        super().__init__(
            owner,
            pairing_data["AccessoryIP"],
            pairing_data["AccessoryPort"],
        )
        self.pairing_data = pairing_data

    @property
    def is_connected(self):
        return super().is_connected and self.is_secure

    async def _connect_once(self):
        """_connect_once must only ever be called from _reconnect to ensure its done with a lock."""
        self.is_secure = False

        if self.owner and self.owner.description:
            pairing = self.owner
            try:
                if self.host != pairing.description.address:
                    logger.debug(
                        "%s: Host changed from %s to %s",
                        pairing.name,
                        self.host,
                        pairing.description.address,
                    )
                    self.host = pairing.description.address

                if self.port != pairing.description.port:
                    logger.debug(
                        "%s: Port changed from %s to %s",
                        pairing.name,
                        self.port,
                        pairing.description.port,
                    )
                    self.port = pairing.description.port
            except AccessoryNotFoundError:
                pass

        await super()._connect_once()

        state_machine = get_session_keys(self.pairing_data)

        request, expected = state_machine.send(None)
        while True:
            try:
                response = await self.post_tlv(
                    "/pair-verify",
                    body=request,
                    expected=expected,
                )
                request, expected = state_machine.send(response)
            except StopIteration as result:
                # If the state machine raises a StopIteration then we have session keys
                _, derive = result.value
                c2a_key = derive(b"Control-Salt", b"Control-Write-Encryption-Key")
                a2c_key = derive(b"Control-Salt", b"Control-Read-Encryption-Key")
                break

        # Secure session has been negotiated - switch protocol so all future messages are encrypted
        self.protocol = SecureHomeKitProtocol(
            self,
            a2c_key,
            c2a_key,
        )
        self.transport.set_protocol(self.protocol)
        self.protocol.connection_made(self.transport)

        self.is_secure = True

        logger.debug("Secure connection to %s:%s established", self.host, self.port)

        if self.owner:
            await self.owner.connection_made(True)
