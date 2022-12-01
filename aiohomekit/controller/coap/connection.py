#
# Copyright 2022 aiohomekit team
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
import random
import struct
from typing import Any
import uuid

from aiocoap import Context, Message, resource
from aiocoap.error import NetworkError
from aiocoap.numbers.codes import Code
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

from aiohomekit.exceptions import (
    AccessoryDisconnectedError,
    AuthenticationError,
    EncryptionError,
    UnknownError,
)
from aiohomekit.protocol import (
    get_session_keys,
    perform_pair_setup_part1,
    perform_pair_setup_part2,
)
from aiohomekit.protocol.tlv import HAP_TLV, TLV
from aiohomekit.utils import asyncio_timeout

from .pdu import (
    OpCode,
    PDUStatus,
    decode_all_pdus,
    decode_pdu,
    encode_all_pdus,
    encode_pdu,
)
from .structs import Pdu09Database

logger = logging.getLogger(__name__)


def decode_pdu_03(buf):
    return bytes(dict(TLV.decode_bytes(buf)).get(HAP_TLV.kTLVHAPParamValue))


def decode_list_pairings_response(buf):
    inner_bytes = decode_pdu_03(buf)
    return TLV.decode_bytes(inner_bytes)


class EncryptionContext:

    coap_ctx: Context
    lock: asyncio.Lock
    uri: str

    event_ctr: int
    event_ctx: ChaCha20Poly1305
    recv_ctr: int
    recv_ctx: ChaCha20Poly1305
    send_ctr: int
    send_ctx: ChaCha20Poly1305

    def __init__(self, recv_ctx, send_ctx, event_ctx, uri, coap_ctx):
        self.recv_ctr = 0
        self.recv_ctx = recv_ctx
        self.send_ctr = 0
        self.send_ctx = send_ctx
        self.event_ctr = 0
        self.event_ctx = event_ctx

        self.coap_ctx = coap_ctx
        self.lock = asyncio.Lock()
        self.uri = uri

    def decrypt(self, enc_data: bytes) -> bytes:
        logger.debug("DECRYPT counter=%d" % (self.recv_ctr,))
        dec_data = self.recv_ctx.decrypt(
            struct.pack("=4xQ", self.recv_ctr), enc_data, b""
        )
        self.recv_ctr += 1
        return dec_data

    def decrypt_event(self, enc_data: bytes) -> bytes:
        dec_data = self.event_ctx.decrypt(
            struct.pack("=4xQ", self.event_ctr), enc_data, b""
        )
        self.event_ctr += 1
        return dec_data

    def encrypt(self, dec_data: bytes) -> bytes:
        logger.debug("ENCRYPT counter=%d" % (self.send_ctr,))
        enc_data = self.send_ctx.encrypt(
            struct.pack("=4xQ", self.send_ctr), dec_data, b""
        )
        self.send_ctr += 1
        return enc_data

    async def _decrypt_response(self, response: Message):
        try:
            return self.decrypt(response.payload)
        except InvalidTag:
            logger.error(
                "Decryption failed, desynchronized? Counter=%d/%d"
                % (self.recv_ctr, self.send_ctr)
            )

            # look back a few counter values
            rewind = min(5, self.recv_ctr)
            self.recv_ctr -= rewind
            for i in range(rewind):
                logger.debug("Attempting to recover by rewind, try %d" % (i + 1,))
                try:
                    return self.decrypt(response.payload)
                except InvalidTag:
                    self.recv_ctr += 1

            # fast forward a few counter values
            for i in range(5):
                logger.debug("Attempting to recover, try %d" % (i + 1,))
                try:
                    # attempt to resynchronize by moving the counter forward
                    # we've got to roll it forward ourselves as the exception prevents that
                    self.recv_ctr += 1
                    return self.decrypt(response.payload)
                except InvalidTag:
                    pass

            # try zeroing out the counters
            try:
                self.recv_ctr = 0
                self.send_ctr = 0
                return self.decrypt(response.payload)
            except InvalidTag:
                pass

            logger.error(
                "Failed flailing attempts to resynchronize, self-destructing in 3, 2, 1..."
            )

            await self.coap_ctx.shutdown()
            self.coap_ctx = None
            raise EncryptionError("Decryption of PDU POST response failed")

    async def post_bytes(self, payload: bytes, timeout: int = 16.0):
        async with self.lock:
            payload = self.encrypt(payload)

            try:
                request = Message(code=Code.POST, payload=payload, uri=self.uri)
                async with asyncio_timeout(timeout):
                    response = await self.coap_ctx.request(request).response
            except (NetworkError, asyncio.TimeoutError):
                raise AccessoryDisconnectedError("Request timeout")

            if response.code != Code.CHANGED:
                logger.warning(f"CoAP POST returned unexpected code {response}")

            return await self._decrypt_response(response)

    async def post(
        self, opcode: OpCode, iid: int, data: bytes
    ) -> tuple[int, bytes | PDUStatus]:
        tid = random.randint(1, 254)
        req_pdu = encode_pdu(opcode, tid, iid, data)
        res_pdu = await self.post_bytes(req_pdu)
        return decode_pdu(tid, res_pdu)

    async def post_all(
        self, opcode: OpCode, iids: list[int], data: list[bytes]
    ) -> list[bytes | PDUStatus]:
        req_pdu = encode_all_pdus(opcode, iids, data)
        res_pdu = await self.post_bytes(req_pdu)
        return decode_all_pdus(0, res_pdu)


class EventResource(resource.Resource):
    def __init__(self, connection):
        super().__init__()
        self.connection = connection

    async def render_put(self, request):
        try:
            payload = self.connection.enc_ctx.decrypt_event(request.payload)
        except InvalidTag:
            logger.warning(
                "Event decryption failed, desynchronized? Counter=%d"
                % (self.connection.enc_ctx.event_ctr,)
            )
            # XXX invalidate subscriptions, etc
            return Message(code=Code.NOT_FOUND)

        logger.debug(f"CoAP event: {payload.hex()}")

        offset = 0
        while True:
            _, iid, body_len = struct.unpack("<BHH", payload[offset : offset + 5])
            body = payload[offset + 5 : offset + 5 + body_len]

            characteristic = self.connection.info.find_characteristic_by_iid(iid)
            value = decode_pdu_03(body) if body_len > 0 else b""
            if characteristic is not None and body_len > 0:
                characteristic.raw_value = value
                value = characteristic.value
            logger.debug("event ?/%d = %r" % (iid, value))

            if self.connection.owner:
                # XXX aid
                key = (1, iid)
                self.connection.owner.event_received(
                    {
                        key: {
                            "value": value,
                        }
                    }
                )

            offset += 5 + body_len
            if offset >= len(payload):
                break

        return Message(code=Code.VALID)


class CoAPHomeKitConnection:
    def __init__(self, owner, host, port):
        self.address = f"[{host}]:{port}"
        self.connection_lock = asyncio.Lock()
        self.enc_ctx = None
        self.owner = owner
        self.pair_setup_client = None

    async def reconnect_soon(self):
        if not self.enc_ctx:
            return
        await self.enc_ctx.coap_ctx.shutdown()
        self.enc_ctx = None
        # XXX can't .connect here w/o pairing_data

    async def do_identify(self):
        client = await Context.create_client_context()
        uri = "coap://%s/0" % (self.address)

        request = Message(code=Code.POST, payload=b"", uri=uri)
        async with asyncio_timeout(4.0):
            response = await client.request(request).response

        await client.shutdown()
        client = None

        return response.code == Code.CHANGED

    async def do_pair_setup(self, with_auth):
        self.pair_setup_client = await Context.create_client_context()
        uri = "coap://%s/1" % (self.address)
        logger.debug(f"Pair setup 1/2 uri={uri}")

        state_machine = perform_pair_setup_part1(with_auth)
        request, expected = state_machine.send(None)
        while True:
            try:
                payload = TLV.encode_list(request)
                request = Message(code=Code.POST, payload=payload, uri=uri)
                # some operations can take some time
                async with asyncio_timeout(16.0):
                    response = await self.pair_setup_client.request(request).response
                payload = TLV.decode_bytes(response.payload, expected=expected)

                request, expected = state_machine.send(payload)
            except StopIteration as result:
                salt, srpB = result.value
                return salt, srpB
            except Exception:
                logger.warning("Pair setup 1/2 failed!")
                await self.pair_setup_client.shutdown()
                raise

    async def do_pair_setup_finish(self, pin, salt, srpB):
        uri = "coap://%s/1" % (self.address)
        logger.debug(f"Pair setup 2/2 uri={uri}")

        state_machine = perform_pair_setup_part2(pin, str(uuid.uuid4()), salt, srpB)
        request, expected = state_machine.send(None)
        while True:
            try:
                payload = TLV.encode_list(request)
                request = Message(code=Code.POST, payload=payload, uri=uri)
                async with asyncio_timeout(16.0):
                    response = await self.pair_setup_client.request(request).response

                payload = TLV.decode_bytes(response.payload, expected=expected)

                request, expected = state_machine.send(payload)
            except StopIteration as result:
                pairing = result.value
                break
            except Exception:
                logger.warning("Pair setup 2/2 failed!")
                await self.pair_setup_client.shutdown()
                raise

        logger.debug(f"Paired with CoAP HAP accessory at {self.address}!")
        await self.pair_setup_client.shutdown()
        self.pair_setup_client = None

        return pairing

    async def do_pair_verify(self, pairing_data):
        if self.is_connected:
            logger.warning("Connecting to connected device?")
            await self.enc_ctx.coap_ctx.shutdown()
            self.enc_ctx = None

        root = resource.Site()
        coap_client = await Context.create_server_context(root, bind=("::", 0))
        uri = "coap://%s/2" % (self.address)
        logger.debug(f"Pair verify uri={uri}")

        state_machine = get_session_keys(pairing_data)

        request, expected = state_machine.send(None)
        while True:
            try:
                payload = TLV.encode_list(request)
                request = Message(code=Code.POST, payload=payload, uri=uri)
                async with asyncio_timeout(8.0):
                    response = await coap_client.request(request).response

                payload = TLV.decode_bytes(response.payload, expected=expected)

                request, expected = state_machine.send(payload)
            except StopIteration as result:
                _, derive = result.value
                break
            except Exception:
                # clean up coap context
                await coap_client.shutdown()
                coap_client = None
                # re-raise any exception
                raise

        recv_key = derive(b"Control-Salt", b"Control-Read-Encryption-Key")
        recv_ctx = ChaCha20Poly1305(recv_key)
        send_key = derive(b"Control-Salt", b"Control-Write-Encryption-Key")
        send_ctx = ChaCha20Poly1305(send_key)
        event_key = derive(b"Event-Salt", b"Event-Read-Encryption-Key")
        event_ctx = ChaCha20Poly1305(event_key)

        uri = "coap://%s/" % (self.address)

        self.enc_ctx = EncryptionContext(
            recv_ctx, send_ctx, event_ctx, uri, coap_client
        )

        logger.debug(f"Connected to CoAP HAP accessory at {self.address}!")
        root.add_resource([], EventResource(self))

        return True

    async def connect(self, pairing_data):
        async with self.connection_lock:
            if self.is_connected:
                logger.debug("Already connected")
                return

            try:
                await self.do_pair_verify(pairing_data)
            except asyncio.TimeoutError:
                logger.warning("Pair verify timed out")
                raise AccessoryDisconnectedError("Pair verify timed out")
            except Exception as exc:
                logger.warning("Pair verify failed", exc_info=exc)
                raise AccessoryDisconnectedError("Pair verify failed")

            # we need the info this provides to be able to read/write characteristics
            await self.get_accessory_info()

            return

    @property
    def is_connected(self):
        return self.enc_ctx is not None and self.enc_ctx.coap_ctx is not None

    async def get_accessory_info(self):
        _, body = await self.enc_ctx.post(OpCode.UNK_09_READ_GATT, 0x0000, b"")

        try:
            self.info = Pdu09Database.decode(body)
            logger.debug(f"Get accessory info: {self.info.to_dict()!r}")
        except Exception as exc:
            logger.error(f"TLV decode failed: {body.hex()}", exc_info=exc)
            raise AccessoryDisconnectedError("Unable to parse accessory database")

        # read all values
        for accessory in self.info.accessories:
            # one service at a time
            for service in accessory.services:
                # first, collect all readable characteristics
                readable = [
                    char
                    for char in service.characteristics
                    if char.supports_secure_reads
                ]

                # get instance IDs
                iids = [char.instance_id for char in readable]

                # make a list of zero length byte strings
                data = [b""] * len(iids)

                # send the read requests
                results = await self.enc_ctx.post_all(OpCode.CHAR_READ, iids, data)

                for (idx, result) in enumerate(results):
                    if isinstance(result, bytes):
                        # success, let's convert the value
                        value = decode_pdu_03(result) if len(result) > 0 else b""
                        readable[idx].raw_value = value
                        logger.debug(
                            "Read value for %X.%X iid %d: value %r"
                            % (
                                service.type,
                                readable[idx].type,
                                readable[idx].instance_id,
                                readable[idx].value,
                            )
                        )
                    else:
                        # characteristic wasn't readable
                        logger.debug(
                            "Failed to read %X.%X iid %d"
                            % (
                                service.type,
                                readable[idx].type,
                                readable[idx].instance_id,
                            )
                        )

        return self.info.to_dict()

    def _read_characteristics_exit(
        self, ids: list[tuple[int, int]], pdu_results: list[bytes | PDUStatus]
    ) -> dict:
        results = dict()
        for (idx, result) in enumerate(pdu_results):
            aid_iid = ids[idx]
            if isinstance(result, PDUStatus):
                logger.debug(
                    "Failed to read aid %d iid %d" % (int(aid_iid[0]), int(aid_iid[1]))
                )
                results[aid_iid] = {
                    "description": result.description,
                    "status": -result.value,  # XXX
                }
            else:
                # decode TLV to get byte value
                value = decode_pdu_03(result) if len(result) > 0 else b""
                # find characteristic so we can get the data type
                characteristic = self.info.find_characteristic_by_iid(int(aid_iid[1]))
                # if we found it & have a non-empty value...
                if characteristic is not None and len(result) > 0:
                    # set the raw bytes
                    characteristic.raw_value = value
                    # and get the decoded value
                    value = characteristic.value
                # add result to dict
                results[aid_iid] = {
                    "value": value,
                }
                logger.debug(
                    "Read value for aid %d iid %d: value %r"
                    % (
                        int(aid_iid[0]),
                        int(aid_iid[1]),
                        value,
                    )
                )

        logger.debug(f"Read characteristics: {results!r}")
        return results

    async def read_characteristics(self, ids: list[tuple[int, int]]):
        iids = [int(aid_iid[1]) for aid_iid in ids]
        data = [b""] * len(iids)
        pdu_results = await self.enc_ctx.post_all(OpCode.CHAR_READ, iids, data)
        return self._read_characteristics_exit(ids, pdu_results)

    def _write_characteristics_enter(
        self, ids_values: list[tuple[int, int, Any]]
    ) -> list[bytearray]:
        # convert provided values to appropriate binary format for each characteristic
        tlv_values = list()
        for (_, aid_iid_value) in enumerate(ids_values):
            # look up characteristic
            characteristic = self.info.find_characteristic_by_aid_iid(
                int(aid_iid_value[0]), int(aid_iid_value[1])
            )
            # write value to cache + convert to appropriate binary representation
            characteristic.value = aid_iid_value[2]
            # get the converted value
            value = characteristic.raw_value
            # encode into TLV
            value_tlv = TLV.encode_list([(HAP_TLV.kTLVHAPParamValue, value)])
            # add to list
            tlv_values.append(value_tlv)

        return tlv_values

    def _write_characteristics_exit(
        self,
        ids_values: list[tuple[int, int, Any]],
        pdu_results: list[bytes | PDUStatus],
    ) -> dict:
        # transform results
        # only error conditions are returned
        results = dict()
        for (idx, result) in enumerate(pdu_results):
            aid_iid_value = ids_values[idx]
            key = (aid_iid_value[0], aid_iid_value[1])
            if isinstance(result, PDUStatus):
                results[key] = {
                    "descripton": result.description,
                    "status": -result.value,  # XXX
                }
            else:
                logger.debug(
                    "Wrote value for aid %d iid %d"
                    % (
                        int(aid_iid_value[0]),
                        int(aid_iid_value[1]),
                    )
                )

        return results

    async def write_characteristics(self, ids_values: list[tuple[int, int, Any]]):
        tlv_values = self._write_characteristics_enter(ids_values)

        # batch write
        pdu_results = await self.enc_ctx.post_all(
            OpCode.CHAR_WRITE,
            [int(aid_iid_value[1]) for aid_iid_value in ids_values],
            tlv_values,
        )

        return self._write_characteristics_exit(ids_values, pdu_results)

    def _subscribe_to_exit(
        self, ids: list[tuple[int, int]], pdu_results: list[bytes | PDUStatus]
    ) -> dict:
        results = dict()
        for (idx, result) in enumerate(pdu_results):
            aid_iid = ids[idx]
            key = (aid_iid[0], aid_iid[1])
            if isinstance(result, PDUStatus):
                results[key] = {
                    "descripton": result.description,
                    "status": -result.value,  # XXX
                }
            else:
                logger.debug(
                    "Subscribed to aid %d iid %d"
                    % (
                        int(aid_iid[0]),
                        int(aid_iid[1]),
                    )
                )

        return results

    async def subscribe_to(self, ids: list[tuple[int, int]]):
        iids = [int(aid_iid[1]) for aid_iid in ids]
        data = [b""] * len(iids)
        pdu_results = await self.enc_ctx.post_all(OpCode.UNK_0B_SUBSCRIBE, iids, data)
        return self._subscribe_to_exit(ids, pdu_results)

    def _unsubscribe_from_exit(
        self, ids: list[tuple[int, int]], pdu_results: list[bytes | PDUStatus]
    ) -> dict:
        results = dict()
        for (idx, result) in enumerate(pdu_results):
            aid_iid = ids[idx]
            key = (aid_iid[0], aid_iid[1])
            if isinstance(result, PDUStatus):
                results[key] = {
                    "descripton": result.description,
                    "status": -result.value,  # XXX
                }
            else:
                logger.debug(
                    "Unsubscribed from aid %d iid %d"
                    % (
                        int(aid_iid[0]),
                        int(aid_iid[1]),
                    )
                )

        return results

    async def unsubscribe_from(self, ids: list[tuple[int, int]]):
        if not ids:
            return {}
        iids = [int(aid_iid[1]) for aid_iid in ids]
        data = [b""] * len(iids)
        pdu_results = await self.enc_ctx.post_all(OpCode.UNK_0C_UNSUBSCRIBE, iids, data)
        return self._unsubscribe_from_exit(ids, pdu_results)

    async def list_pairings(self):
        pairings_characteristic = self.info.accessories[
            0
        ].find_service_characteristic_by_type(0x55, 0x50)

        # list pairings M1
        m1_payload = TLV.encode_list(
            [
                (TLV.kTLVType_State, TLV.M1),
                (TLV.kTLVType_Method, TLV.ListPairings),
            ]
        )
        payload = TLV.encode_list([(HAP_TLV.kTLVHAPParamValue, m1_payload)])
        payload_len, payload = await self.enc_ctx.post(
            OpCode.CHAR_WRITE,
            pairings_characteristic.instance_id,
            payload,
        )
        # XXX check response

        payload_len, payload = await self.enc_ctx.post(
            OpCode.CHAR_READ,
            pairings_characteristic.instance_id,
            b"",
        )
        # XXX check response

        # list pairings M2
        m2 = decode_list_pairings_response(payload)

        m2_state = list(filter(lambda x: x[0] == TLV.kTLVType_State, m2))
        if len(m2_state) != 1 or m2_state[0][1] != TLV.M2:
            logger.warning("Unexpected state in list pairings M2")
            return

        m2_error = list(filter(lambda x: x[0] == TLV.kTLVType_Error, m2))
        if len(m2_error) != 0:
            logger.warning(
                f"Error from accessory during list pairings: {m2_error[0][1]}"
            )
            return

        id_list = [
            pairing_tuple[1]
            for pairing_tuple in m2
            if pairing_tuple[0] == TLV.kTLVType_Identifier
        ]
        pk_list = [
            pairing_tuple[1]
            for pairing_tuple in m2
            if pairing_tuple[0] == TLV.kTLVType_PublicKey
        ]
        pr_list = [
            int.from_bytes(pairing_tuple[1], byteorder="little")
            for pairing_tuple in m2
            if pairing_tuple[0] == TLV.kTLVType_Permissions
        ]
        return list(zip(id_list, pk_list, pr_list))

    async def remove_pairing(self, pairing_id) -> bool:
        pairings_characteristic = self.info.accessories[
            0
        ].find_service_characteristic_by_type(0x55, 0x50)

        # remove pairings M1
        m1_payload = TLV.encode_list(
            [
                (TLV.kTLVType_State, TLV.M1),
                (TLV.kTLVType_Method, TLV.RemovePairing),
                (TLV.kTLVType_Identifier, pairing_id.encode()),
            ]
        )
        payload = TLV.encode_list([(HAP_TLV.kTLVHAPParamValue, m1_payload)])
        result_len, result = await self.enc_ctx.post(
            OpCode.CHAR_WRITE,
            pairings_characteristic.instance_id,
            payload,
        )

        # iOS didn't retrieve M2 from the pairings characteristic
        if isinstance(result, PDUStatus):
            if result in [
                PDUStatus.INSUFFICIENT_AUTHENTICATION,
                PDUStatus.INSUFFICIENT_AUTHORIZATION,
            ]:
                raise AuthenticationError("Remove pairing failed")
            else:
                raise UnknownError("Remove pairing failed")

        return True
