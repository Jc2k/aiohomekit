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
from typing import TYPE_CHECKING, Any
import uuid

from bleak import BleakClient
from bleak.exc import BleakError

from aiohomekit.controller.ble.client import (
    ble_request,
    drive_pairing_state_machine,
    get_characteristic,
)
from aiohomekit.exceptions import AuthenticationError, InvalidError, UnknownError
from aiohomekit.model import Accessories, Accessory, CharacteristicsTypes
from aiohomekit.model.characteristics import CharacteristicPermissions
from aiohomekit.model.services import ServicesTypes
from aiohomekit.pdu import OpCode, decode_pdu, encode_pdu
from aiohomekit.protocol import get_session_keys
from aiohomekit.protocol.statuscodes import HapStatusCode
from aiohomekit.protocol.tlv import TLV
from aiohomekit.utils import async_create_task
from aiohomekit.uuid import normalize_uuid

from ..abstract import AbstractPairing
from .key import DecryptionKey, EncryptionKey
from .manufacturer_data import HomeKitAdvertisement
from .structs import Characteristic as CharacteristicTLV
from .values import from_bytes, to_bytes

if TYPE_CHECKING:
    from aiohomekit.controller.ble.controller import BleController

logger = logging.getLogger(__name__)

SERVICE_INSTANCE_ID = "E604E95D-A759-4817-87D3-AA005083A0D1"


class BlePairing(AbstractPairing):
    """
    This represents a paired HomeKit IP accessory.
    """

    pairing_id: str
    description: HomeKitAdvertisement | None
    controller: BleController

    _accessories: Accessories | None = None

    _encryption_key: EncryptionKey | None = None
    _decryption_key: DecryptionKey | None = None

    client: BleakClient | None = None

    # Used to keep track of which characteristics we already started
    # notifications for
    _notifications: set[int]

    # We don't want to read/write from characteristics in parallel
    # * If 2 coroutines read from the same char at the same time there
    #   would be a race error - a read result could be overwritten by another.
    # * The enc/dec counters are global. Therefore our API's for
    #   a read/write need to be atomic otherwise we end up having
    #   to guess what encryption counter to use for the decrypt
    _lock: asyncio.Lock

    def __init__(self, controller: BleController, pairing_data):
        super().__init__(controller)

        self.id = pairing_data["AccessoryPairingID"]

        if cache := self.controller._char_cache.get_map(self.id):
            self._accessories = Accessories.from_list(cache["accessories"])

        self.pairing_data = pairing_data

        self._session_id = None
        self._derive = None

        self._notifications = set()
        self._lock = asyncio.Lock()

    def _async_description_update(self, description: HomeKitAdvertisement | None):
        if description and self.description:
            if description.config_num > self.description.config_num:
                logger.debug("Config number has changed; char cache invalid")

            if description.state_num > self.description.state_num:
                logger.debug(
                    "Disconnected event notification received; Triggering catch-up poll"
                )
                async_create_task(self._async_process_disconnected_events())

            if description.address != self.description.address:
                logger.debug(
                    "BLE address changed from %s to %s; closing connection",
                    self.description.address,
                    description.address,
                )
                async_create_task(self.close())

        return super()._async_description_update(description)

    @property
    def is_connected(self) -> bool:
        return self.client and self.client.is_connected and self._encryption_key

    async def _async_request(
        self, opcode: OpCode, iid: int, data: bytes | None = None
    ) -> bytes:
        char = self._accessories.aid(1).characteristics.iid(iid)
        endpoint = get_characteristic(self.client, char.service.type, char.type)
        return await ble_request(
            self.client,
            self._encryption_key,
            self._decryption_key,
            opcode,
            endpoint.handle,
            iid,
            data,
        )

    def _async_disconnected(self, *args, **kwargs):
        logger.debug("Session closed")

    async def _ensure_connected(self):
        while not self.client or not self.client.is_connected:
            if self.client:
                await self.close()

            if self.description:
                address = self.description.address
            else:
                address = self.pairing_data["AccessoryAddress"]

            self.client = BleakClient(address)
            self.client.set_disconnected_callback(self._async_disconnected)

            try:
                await self.client.connect()
            except BleakError as e:
                logger.debug("Failed to connect to %s: %s", self.client.address, str(e))
                self.client = None
                await asyncio.sleep(5)

        if not self._accessories:
            self._accessories = await self._async_fetch_gatt_database()
            self.controller._char_cache.async_create_or_update_map(
                self.id,
                0,
                self._accessories.serialize(),
            )

        if not self._encryption_key:
            await self._async_pair_verify()

        for (aid, iid) in list(self.subscriptions):
            if iid not in self._notifications:
                await self._async_start_notify(iid)

    async def _async_start_notify(self, iid: int) -> None:
        if not self._accessories:
            return

        char = self._accessories.aid(1).characteristics.iid(iid)

        # Find the GATT Characteristic object for this iid
        service = self.client.services.get_service(char.service.type)
        endpoint = service.get_characteristic(char.type)

        async def _async_callback() -> None:
            logger.debug("Retrieving event for iid: %s", iid)
            results = await self.get_characteristics([(1, iid)])
            for listener in self.listeners:
                listener(results)

        def _callback(id, data) -> None:
            async_create_task(_async_callback())

        logger.debug("Subscribing to iid: %s", iid)
        await self.client.start_notify(endpoint, _callback)
        self._notifications.add(iid)

    async def _async_pair_verify(self):
        session_id, derive = await drive_pairing_state_machine(
            self.client,
            CharacteristicsTypes.PAIR_VERIFY,
            get_session_keys(self.pairing_data, self._session_id, self._derive),
        )
        self._encryption_key = EncryptionKey(
            derive(b"Control-Salt", b"Control-Write-Encryption-Key")
        )
        self._decryption_key = DecryptionKey(
            derive(b"Control-Salt", b"Control-Read-Encryption-Key")
        )

        # Used for session resume
        self._session_id = session_id
        self._derive = derive

    async def _async_process_disconnected_events(self) -> None:
        logger.debug("Polling subscriptions for changes during disconnection")
        results = await self.get_characteristics(list(self.subscriptions))
        for listener in self.listeners:
            listener(results)

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
                for data in encode_pdu(
                    OpCode.CHAR_SIG_READ,
                    tid,
                    iid,
                ):
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
        if self.client:
            await self.client.disconnect()
            self.client = None
            self._notifications = set()

        self._encryption_key = None
        self._decryption_key = None

    async def list_accessories_and_characteristics(self):
        async with self._lock:
            await self._ensure_connected()
        results = self._accessories.serialize()
        return results

    async def list_pairings(self):
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

        async with self._lock:
            await self._ensure_connected()
            resp = await self._async_request(OpCode.CHAR_WRITE, char.iid, request_tlv)

        response = dict(TLV.decode_bytes(resp))

        resp = TLV.decode_bytes(response[1])

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
    ) -> dict[tuple[int, int], Any]:
        await self._ensure_connected()

        results = {}

        for aid, iid in characteristics:
            data = await self._async_request(OpCode.CHAR_READ, iid)
            data = dict(TLV.decode_bytes(data))[1]

            char = self._accessories.aid(1).characteristics.iid(iid)
            results[(aid, iid)] = {"value": from_bytes(char, data)}

        return results

    async def put_characteristics(
        self, characteristics: list[tuple[int, int, Any]]
    ) -> dict[tuple[int, int], Any]:
        await self._ensure_connected()

        results: dict[tuple[int, int], Any] = {}

        for aid, iid, value in characteristics:
            char = self._accessories.aid(1).characteristics.iid(iid)

            if CharacteristicPermissions.timed_write in char.perms:
                payload = TLV.encode_list([(1, to_bytes(char, value))])
                await self._async_request(OpCode.CHAR_TIMED_WRITE, iid, payload)
                await self._async_request(OpCode.CHAR_EXEC_WRITE, iid)

            elif CharacteristicPermissions.paired_write in char.perms:
                payload = TLV.encode_list([(1, to_bytes(char, value))])
                await self._async_request(OpCode.CHAR_WRITE, iid, payload)

            else:
                results[(aid, iid)] = {
                    "status": HapStatusCode.CANT_WRITE_READ_ONLY,
                    "description": HapStatusCode.CANT_WRITE_READ_ONLY.description,
                }

        return results

    async def subscribe(self, characteristics):
        await super().subscribe(characteristics)
        async with self._lock:
            await self._ensure_connected()

    async def unsubscribe(self, characteristics):
        pass

    async def identify(self):
        async with self._lock:
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
        if permissions == "User":
            permissions = TLV.kTLVType_Permission_RegularUser
        elif permissions == "Admin":
            permissions = TLV.kTLVType_Permission_AdminUser
        else:
            raise RuntimeError(f"Unknown permission: {permissions}")

        request_tlv = TLV.encode_list(
            [
                (TLV.kTLVType_State, TLV.M1),
                (TLV.kTLVType_Method, TLV.AddPairing),
                (
                    TLV.kTLVType_Identifier,
                    additional_controller_pairing_identifier.encode(),
                ),
                (TLV.kTLVType_PublicKey, bytes.fromhex(ios_device_ltpk)),
                (TLV.kTLVType_Permissions, permissions),
            ]
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

        data = dict(TLV.decode_bytes(response[1]))

        if data.get(TLV.kTLVType_State, TLV.M2) != TLV.M2:
            raise InvalidError("Unexpected state after removing pairing request")

        if TLV.kTLVType_Error in data:
            if data[TLV.kTLVType_Error] == TLV.kTLVError_Authentication:
                raise AuthenticationError("Add pairing failed: insufficient access")
            raise UnknownError("Add pairing failed: unknown error")

    async def remove_pairing(self, pairingId: str):
        await self._ensure_connected()

        request_tlv = TLV.encode_list(
            [
                (TLV.kTLVType_State, TLV.M1),
                (TLV.kTLVType_Method, TLV.RemovePairing),
                (TLV.kTLVType_Identifier, pairingId.encode("utf-8")),
            ]
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

        data = dict(TLV.decode_bytes(response[1]))

        if data.get(TLV.kTLVType_State, TLV.M2) != TLV.M2:
            raise InvalidError("Unexpected state after removing pairing request")

        if TLV.kTLVType_Error in data:
            if data[TLV.kTLVType_Error] == TLV.kTLVError_Authentication:
                raise AuthenticationError("Remove pairing failed: insufficient access")
            raise UnknownError("Remove pairing failed: unknown error")

    async def image(self, accessory: int, width: int, height: int) -> None:
        """Bluetooth devices don't return images."""
        return None
