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

import logging
import random
from typing import TYPE_CHECKING, Any
import uuid

from bleak import BleakClient

from aiohomekit.model import Accessories, Accessory, CharacteristicsTypes
from aiohomekit.model.services import ServicesTypes
from aiohomekit.pdu import OpCode, decode_pdu, encode_pdu
from aiohomekit.protocol import get_session_keys
from aiohomekit.protocol.tlv import TLV
from aiohomekit.uuid import normalize_uuid

from ..pairing import AbstractPairing
from .const import AdditionalParameterTypes
from .key import DecryptionKey, EncryptionKey
from .structs import BleRequest, Characteristic as CharacteristicTLV
from .values import from_bytes, to_bytes

if TYPE_CHECKING:
    from aiohomekit.controller import Controller

logger = logging.getLogger(__name__)

SERVICE_INSTANCE_ID = "E604E95D-A759-4817-87D3-AA005083A0D1"


async def do_request(client: BleakClient, handle: int, cid: int, body: bytes):
    body = BleRequest(expect_response=1, value=body).encode()

    transaction_id = random.randrange(0, 255)
    # construct a hap characteristic write request following chapter 7.3.4.4 page 94 spec R2
    data = bytearray([0x00, OpCode.CHAR_WRITE.value, transaction_id])
    data.extend(cid.to_bytes(length=2, byteorder="little"))
    data.extend(len(body).to_bytes(length=2, byteorder="little"))
    data.extend(body)

    await client.write_gatt_char(handle, data)

    data = await client.read_gatt_char(handle)

    expected_length = int.from_bytes(bytes(data[3:5]), byteorder="little")
    while len(data[3:]) < expected_length:
        data += await client.read_gatt_char(handle)

    decoded = dict(TLV.decode_bytes(data[5:]))
    return TLV.decode_bytes(decoded[AdditionalParameterTypes.Value.value])


async def do_pair_verify(client: BleakClient, request):
    service = client.services.get_service(ServicesTypes.PAIRING)
    char = service.get_characteristic(CharacteristicsTypes.PAIR_VERIFY)
    iid_handle = char.get_descriptor(uuid.UUID("DC46F0FE-81D2-4616-B5D9-6ABDD796939A"))
    value = bytes(await client.read_gatt_descriptor(iid_handle.handle))

    body = TLV.encode_list(request)
    new_cid = int.from_bytes(value, byteorder="little")

    return await do_request(client, char.handle, new_cid, body)


class BlePairing(AbstractPairing):
    """
    This represents a paired HomeKit IP accessory.
    """

    pairing_id: str

    controller: Controller

    _accessories: Accessories | None = None

    _encryption_key: EncryptionKey | None = None
    _decryption_key: DecryptionKey | None = None

    def __init__(self, controller: Controller, pairing_data):
        super().__init__(controller)
        self.pairing_id = pairing_data["AccessoryPairingID"]

        self.client = BleakClient(pairing_data["AccessoryAddress"])

        if cache := self.controller._char_cache.get_map(self.pairing_id):
            self._accessories = Accessories.from_list(cache["accessories"])

        self.pairing_data = pairing_data

    async def _async_request(
        self, opcode: OpCode, iid: int, data: bytes | None = None
    ) -> bytes:
        char = self._accessories.aid(1).characteristics.iid(iid)

        svc = self.client.services[char.service.type]
        endpoint = svc.get_characteristic(char.type)

        tid = random.randrange(1, 254)
        data = encode_pdu(opcode, tid, iid, data)

        if self._encryption_key:
            data = self._encryption_key.encrypt(data)

        await self.client.write_gatt_char(endpoint.handle, data)
        resp = await self.client.read_gatt_char(endpoint.handle)

        if self._decryption_key:
            data = self._decryption_key.decrypt(resp)

        exp_length, data = decode_pdu(tid, data)

        return data

    async def _ensure_connected(self):
        if not self.client.is_connected:
            await self.client.__aenter__()

        if not self._accessories:
            self._accessories = await self._async_fetch_gatt_database()
            self.controller._char_cache.async_create_or_update_map(
                self.pairing_id,
                0,
                self._accessories.serialize(),
            )

        if not self._encryption_key:
            await self._async_pair_verify()

    async def _async_pair_verify(self):
        state_machine = get_session_keys(self.pairing_data)

        request, expected = state_machine.send(None)
        while True:
            response = await do_pair_verify(self.client, request)
            try:
                request, expected = state_machine.send(response)
            except StopIteration as result:
                derive = result.value
                self._encryption_key = EncryptionKey(
                    derive("Control-Salt", "Control-Write-Encryption-Key")
                )
                self._decryption_key = DecryptionKey(
                    derive("Control-Salt", "Control-Read-Encryption-Key")
                )
                break

    async def _async_fetch_gatt_database(self) -> Accessories:
        accessory = Accessory()
        accessory.aid = 1

        for service in self.client.services:
            s = accessory.add_service(normalize_uuid(service.uuid))

            for char in service.characteristics:
                if normalize_uuid(char.uuid) == SERVICE_INSTANCE_ID:
                    continue

                iid_handle = char.get_descriptor(
                    uuid.UUID("DC46F0FE-81D2-4616-B5D9-6ABDD796939A")
                )
                if not iid_handle:
                    continue

                iid = int.from_bytes(
                    await self.client.read_gatt_descriptor(iid_handle.handle),
                    byteorder="little",
                )

                tid = random.randint(1, 254)
                data = encode_pdu(OpCode.CHAR_SIG_READ, tid, iid)

                await self.client.write_gatt_char(char.handle, data)
                payload = await self.client.read_gatt_char(char.handle)

                _, signature = decode_pdu(tid, payload)

                decoded = CharacteristicTLV.decode(signature).to_dict()
                char = s.add_char(normalize_uuid(char.uuid))
                char.iid = iid

                char.perms = decoded["perms"]
                char.format = decoded["format"]

        accessories = Accessories()
        accessories.add_accessory(accessory)

        return accessories

    async def close(self):
        pass

    async def list_accessories_and_characteristics(self):
        await self._ensure_connected()

        results = self._accessories.serialize()
        return results

    async def list_pairings(self):
        await self._ensure_connected()

        request_tlv = TLV.encode_list(
            [(TLV.kTLVType_State, TLV.M1), (TLV.kTLVType_Method, TLV.ListPairings)]
        )
        request_tlv = TLV.encode_list(
            [
                (TLV.kTLVHAPParamParamReturnResponse, bytearray(b"\x01")),
                (TLV.kTLVHAPParamValue, request_tlv),
            ]
        )

        info = self._accessories.aid(1).services.first(
            service_type=ServicesTypes.PAIRING
        )
        char = info[CharacteristicsTypes.PAIRING_PAIRINGS]

        resp = await self._async_request(OpCode.CHAR_WRITE, char.iid, request_tlv)

        response = dict(TLV.decode_bytes(resp))

        resp = TLV.decode_bytes(response[1])
        print(resp)

        tmp = []
        r = {}
        for d in resp[1:]:
            if d[0] == TLV.kTLVType_Identifier:
                r = {}
                tmp.append(r)
                r["pairingId"] = d[1].decode()
            if d[0] == TLV.kTLVType_PublicKey:
                r["publicKey"] = d[1].hex()
            if d[0] == TLV.kTLVType_Permissions:
                controller_type = "regular"
                if d[1] == b"\x01":
                    controller_type = "admin"
                r["permissions"] = int.from_bytes(d[1], byteorder="little")
                r["controllerType"] = controller_type
        return tmp

    async def get_characteristics(
        self,
        characteristics: list[tuple[int, int]],
        include_meta=False,
        include_perms=False,
        include_type=False,
        include_events=False,
    ) -> dict[tuple[int, int], Any]:
        await self._ensure_connected()

        results = {}

        for aid, iid in characteristics:
            data = await self._async_request(OpCode.CHAR_READ, iid)
            data = dict(TLV.decode_bytes(data))[1]

            char = self._accessories.aid(1).characteristics.iid(iid)
            results[(aid, iid)] = from_bytes(char, data)

        print(results)

        return {}

    async def put_characteristics(self, characteristics: list[tuple[int, int, Any]]):
        await self._ensure_connected()

        results = {}

        for aid, iid, value in characteristics:
            char = self._accessories.aid(1).characteristics.iid(iid)
            payload = TLV.encode_list([(1, to_bytes(char, value))])

            data = await self._async_request(OpCode.CHAR_WRITE, iid, payload)

            if data:
                data = dict(TLV.decode_bytes(data))[1]

        return results

    async def subscribe(self, characteristics):
        pass

    async def unsubscribe(self, characteristics):
        pass

    async def identify(self):
        await self._ensure_connected()

        info = self._accessories.aid(1).services.first(
            service_type=ServicesTypes.ACCESSORY_INFORMATION
        )
        char = info[CharacteristicsTypes.IDENTIFY]

        await self.put_characteristics(
            [
                (1, char.iid, True),
            ]
        )

    async def add_pairing(
        self, additional_controller_pairing_identifier, ios_device_ltpk, permissions
    ):
        pass

    async def remove_pairing(self, pairingId: str):
        pass

    async def image(self, accessory: int, width: int, height: int) -> None:
        """Bluetooth devices don't return images."""
        return None
