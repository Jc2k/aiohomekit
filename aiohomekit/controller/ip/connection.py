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

import asyncio
import json
import logging

from aiohomekit.crypto.chacha20poly1305 import (
    chacha20_aead_decrypt,
    chacha20_aead_encrypt,
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
from aiohomekit.http import HttpContentTypes
from aiohomekit.http.response import HttpResponse
from aiohomekit.protocol import get_session_keys
from aiohomekit.protocol.tlv import TLV
from aiohomekit.zeroconf import async_find_device_ip_and_port

logger = logging.getLogger(__name__)


def serialize_json(obj) -> bytes:
    """
    An iPhone sends JSON like this:

    {"characteristics":[{"iid":15,"aid":2,"ev":true}]}

    Some devices (Tado Internet Bridge) depend on this some of the time.
    """
    return json.dumps(obj, separators=(",", ":")).encode("utf-8")


class InsecureHomeKitProtocol(asyncio.Protocol):
    def __init__(self, connection):
        self.connection = connection
        self.host = ":".join((connection.host, str(connection.port)))
        self.result_cbs = []
        self.current_response = HttpResponse()

    def connection_made(self, transport):
        super().connection_made(transport)
        self.transport = transport

    def connection_lost(self, exception):
        self.connection._connection_lost(exception)

    async def send_bytes(self, payload):
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
        result = asyncio.Future()
        self.result_cbs.append(result)

        try:
            return await asyncio.wait_for(result, 30)
        except asyncio.TimeoutError:
            self.transport.write_eof()
            self.transport.close()
            raise AccessoryDisconnectedError("Timeout while waiting for response")

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
    def __init__(self, connection, a2c_key, c2a_key):
        super().__init__(connection)

        self._incoming_buffer = bytearray()

        self.c2a_counter = 0
        self.a2c_counter = 0

        self.a2c_key = a2c_key
        self.c2a_key = c2a_key

    async def send_bytes(self, payload):
        buffer = b""

        while len(payload) > 0:
            current = payload[:1024]
            payload = payload[1024:]

            len_bytes = len(current).to_bytes(2, byteorder="little")
            cnt_bytes = self.c2a_counter.to_bytes(8, byteorder="little")
            self.c2a_counter += 1

            data = chacha20_aead_encrypt(
                len_bytes,
                self.c2a_key,
                cnt_bytes,
                bytes([0, 0, 0, 0]),
                current,
            )

            buffer += len_bytes + data

        return await super().send_bytes(buffer)

    def data_received(self, data):
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

            block = self._incoming_buffer[:block_length]
            del self._incoming_buffer[:block_length]
            tag = self._incoming_buffer[:16]
            del self._incoming_buffer[:16]

            decrypted = chacha20_aead_decrypt(
                block_length_bytes,
                self.a2c_key,
                self.a2c_counter.to_bytes(8, byteorder="little"),
                bytes([0, 0, 0, 0]),
                block + tag,
            )

            if decrypted is False:
                # FIXME: Does raising here drop the connection or do we call close on transport ourselves
                raise RuntimeError("Could not decrypt block")

            self.a2c_counter += 1

            super().data_received(decrypted)


class HomeKitConnection:
    def __init__(self, owner, host, port, concurrency_limit=1):
        self.owner = owner
        self.host = host
        self.port = port

        self.closing = False
        self.closed = False
        self._retry_interval = 0.5

        self.transport = None
        self.protocol = None

        self._connector = None

        self.is_secure = False

        self._concurrency_limit = asyncio.Semaphore(concurrency_limit)

    @property
    def is_connected(self):
        return self.transport and self.protocol and not self.closed

    def _start_connector(self):
        """
        Start a reconnect background task.

        This function is *not* thread safe. It should only be called on the main thread
        where the event loop is running. If it is not there is a race where multiple
        reconnect tasks could run at once.

        This function **will not** start another reconnect thread if one is already
        running. Or if it is already connected.
        """
        if self._connector or self.is_connected:
            return

        def done_callback(result):
            self._connector = None
            try:
                result.result()
            except asyncio.CancelledError:
                pass
            except Exception:
                logger.exception("Unhandled error from connecter.")

        self._connector = asyncio.ensure_future(self._reconnect())
        self._connector.add_done_callback(done_callback)

    async def ensure_connection(self):
        """
        Waits for a connection to the device.

        If connected and authenticated returns immediately.

        Otherwise, if a reconnection is in progress wait for it to complete.

        Otherwise, start a reconnection and wait for it.
        """
        if self.is_connected:
            return
        self.closing = False
        self._start_connector()
        await asyncio.shield(self._connector)

    async def _stop_connector(self):
        """
        Cancels any active reconnect tasks.

        If no active reconnect tasks it will return immediately.

        Otherwise it will wait for the task to end.
        """
        if not self._connector:
            return
        self._connector.cancel()
        await self._connector
        self._connector = None

    async def get(self, target):
        """
        Sends a HTTP POST request to the current transport and returns an awaitable
        that can be used to wait for a response.
        """
        return await self.request(
            method="GET",
            target=target,
        )

    async def get_json(self, target):
        response = await self.get(target)
        body = response.body.decode("utf-8")
        return json.loads(body)

    async def put(self, target, body, content_type=HttpContentTypes.JSON):
        """
        Sends a HTTP POST request to the current transport and returns an awaitable
        that can be used to wait for a response.
        """
        return await self.request(
            method="PUT",
            target=target,
            headers=[("Content-Length", len(body)), ("Content-Type", content_type)],
            body=body,
        )

    async def put_json(self, target, body):
        response = await self.put(
            target,
            serialize_json(body),
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
            parsed = json.loads(decoded)
        except json.JSONDecodeError:
            self.transport.close()
            raise AccessoryDisconnectedError(
                "Session closed after receiving malformed response from device"
            )

        return parsed

    async def post(self, target, body, content_type=HttpContentTypes.TLV):
        """
        Sends a HTTP POST request to the current transport and returns an awaitable
        that can be used to wait for a response.
        """
        return await self.request(
            method="POST",
            target=target,
            headers=[("Content-Length", len(body)), ("Content-Type", content_type)],
            body=body,
        )

    async def post_json(self, target, body):
        response = await self.post(
            target,
            serialize_json(body),
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
            parsed = json.loads(decoded)
        except json.JSONDecodeError:
            self.transport.close()
            raise AccessoryDisconnectedError(
                "Session closed after receiving malformed response from device"
            )

        return parsed

    async def post_tlv(self, target, body, expected=None):
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

    async def request(self, method, target, headers=None, body=None):
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
            for (header, value) in headers:
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

    async def close(self):
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

    def _connection_lost(self, exception):
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

    async def _connect_once(self):
        loop = asyncio.get_event_loop()

        logger.debug("Attempting connection to %s:%s", self.host, self.port)

        try:
            self.transport, self.protocol = await asyncio.wait_for(
                loop.create_connection(
                    lambda: InsecureHomeKitProtocol(self), self.host, self.port
                ),
                timeout=10,
            )

        except asyncio.TimeoutError:
            raise TimeoutError("Timeout")

        except OSError as e:
            raise ConnectionError(str(e))

        if self.owner:
            await self.owner.connection_made(False)

    async def _reconnect(self):
        # FIXME: How to integrate discovery here?
        # There is aiozeroconf but that doesn't work on Windows until python 3.9
        # In HASS, zeroconf is a service provided by HASS itself and want to be able to
        # leverage that instead.
        interval = 0.5

        while not self.closing:
            try:
                return await self._connect_once()

            except AuthenticationError:
                # Authentication errors should bubble up because auto-reconnect is unlikely to help
                raise

            except asyncio.CancelledError:
                return

            except HomeKitException:
                logger.debug(
                    "Connecting to accessory failed. Retrying in %i seconds", interval
                )

            except Exception:
                logger.exception(
                    "Unexpected error whilst trying to connect to accessory. Will retry."
                )

            interval = min(60, 1.5 * interval)
            await asyncio.sleep(interval)

    def event_received(self, event):
        if not self.owner:
            return

        # FIXME: Should drop the connection if can't parse the event?

        decoded = event.body.decode("utf-8")
        if not decoded:
            return

        try:
            parsed = json.loads(decoded)
        except json.JSONDecodeError:
            return

        self.owner.event_received(parsed)

    def __repr__(self):
        return f"HomeKitConnection(host={self.host!r}, port={self.port!r})"


class SecureHomeKitConnection(HomeKitConnection):
    def __init__(self, owner, pairing_data):
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
        self.is_secure = False

        try:
            self.host, self.port = await async_find_device_ip_and_port(
                self.pairing_data["AccessoryPairingID"],
                zeroconf_instance=self.owner.controller._zeroconf_instance,
            )
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
                c2a_key, a2c_key = result.value
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
