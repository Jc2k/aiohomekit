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
from typing import TYPE_CHECKING, Any
import uuid

from bleak import BleakClient
from bleak.exc import BleakError

from aiohomekit.controller.ble.client import (
    ble_request,
    drive_pairing_state_machine,
    get_characteristic,
    retry_bleak_error,
)
from aiohomekit.exceptions import (
    AccessoryDisconnectedError,
    AuthenticationError,
    InvalidError,
    UnknownError,
)
from aiohomekit.model import (
    Accessories,
    AccessoriesState,
    Accessory,
    CharacteristicsTypes,
)
from aiohomekit.model.characteristics import CharacteristicPermissions
from aiohomekit.model.services import ServicesTypes
from aiohomekit.pdu import OpCode, PDUStatus, decode_pdu, encode_pdu
from aiohomekit.protocol import get_session_keys
from aiohomekit.protocol.statuscodes import HapStatusCode
from aiohomekit.protocol.tlv import TLV
from aiohomekit.utils import async_create_task
from aiohomekit.uuid import normalize_uuid

from ..abstract import AbstractPairing
from .connection import establish_connection
from .key import DecryptionKey, EncryptionKey
from .manufacturer_data import HomeKitAdvertisement
from .structs import HAP_TLV, Characteristic as CharacteristicTLV
from .values import from_bytes, to_bytes

if TYPE_CHECKING:
    from aiohomekit.controller.ble.controller import BleController

logger = logging.getLogger(__name__)

SERVICE_INSTANCE_ID = "E604E95D-A759-4817-87D3-AA005083A0D1"
MAX_CONNECT_ATTEMPTS = 3
SKIP_SYNC_SERVICES = {
    ServicesTypes.THREAD_TRANSPORT,
    ServicesTypes.PAIRING,
    ServicesTypes.TRANSFER_TRANSPORT_MANAGEMENT,
}


class BlePairing(AbstractPairing):
    """
    This represents a paired HomeKit IP accessory.
    """

    pairing_id: str
    description: HomeKitAdvertisement | None
    controller: BleController

    _encryption_key: EncryptionKey | None = None
    _decryption_key: DecryptionKey | None = None

    client: BleakClient | None = None

    # Used to keep track of which characteristics we already started
    # notifications for
    _notifications: set[int]

    def __init__(self, controller: BleController, pairing_data):
        super().__init__(controller)

        self.id = pairing_data["AccessoryPairingID"]

        self.pairing_data = pairing_data

        self._session_id = None
        self._derive = None

        self._notifications = set()
        self._connection_lock = asyncio.Lock()

        # We don't want to read/write from characteristics in parallel
        # * If 2 coroutines read from the same char at the same time there
        #   would be a race error - a read result could be overwritten by another.
        # * The enc/dec counters are global. Therefore our API's for
        #   a read/write need to be atomic otherwise we end up having
        #   to guess what encryption counter to use for the decrypt
        self._ble_request_lock = asyncio.Lock()

        self._config_lock = asyncio.Lock()

    def get_address(self) -> str:
        """Return the most current address for the device."""
        return self.address

    @property
    def address(self):
        return (
            self.description.address
            if self.description
            else self.pairing_data["AccessoryAddress"]
        )

    @property
    def name(self):
        if self.description:
            return f"{self.description.name} ({self.address})"
        return self.address

    @property
    def is_connected(self) -> bool:
        return self.client and self.client.is_connected and self._encryption_key

    def _async_description_update(self, description: HomeKitAdvertisement | None):
        if self.description != description:
            logger.debug("%s: Description updated: %s", self.address, description)
        repopulate_accessories = False
        if description and self.description:
            if description.config_num > self.description.config_num:
                logger.debug(
                    "%s: Config number has changed from %s to %s; char cache invalid",
                    self.name,
                    self.description.config_num,
                    description.config_num,
                )
                repopulate_accessories = True

            if description.state_num > self.description.state_num:
                logger.debug(
                    "%s: Disconnected event notification received; Triggering catch-up poll",
                    self.name,
                )
                async_create_task(self._async_process_disconnected_events())

            if description.address != self.description.address:
                logger.debug(
                    "BLE address changed from %s to %s; closing connection",
                    self.description.address,
                    description.address,
                )
                async_create_task(self.close())

        super()._async_description_update(description)
        if repopulate_accessories:
            async_create_task(self._populate_accessories_and_characteristics())

    async def _async_request(
        self, opcode: OpCode, iid: int, data: bytes | None = None
    ) -> bytes:
        char = self._accessories.aid(1).characteristics.iid(iid)
        endpoint = get_characteristic(self.client, char.service.type, char.type)
        async with self._ble_request_lock:
            if not self.client or not self.client.is_connected:
                logger.debug("%s: Client not connected", self.name)
                raise AccessoryDisconnectedError(f"{self.name} is not connected")
            pdu_status, result_data = await ble_request(
                self.client,
                self._encryption_key,
                self._decryption_key,
                opcode,
                endpoint.handle,
                iid,
                data,
            )
            if pdu_status != PDUStatus.SUCCESS:
                raise ValueError(
                    f"{self.name}: PDU status was not success: {pdu_status.description} ({pdu_status.value})"
                )
            return result_data

    def _async_disconnected(self, client: BleakClient) -> None:
        """Called when bleak disconnects from the accessory closed the connection."""
        logger.debug("%s: Session closed callback", self.name)
        self._async_reset_connection_state()

    def _async_reset_connection_state(self) -> None:
        """Reset the connection state after a disconnect."""
        self._encryption_key = None
        self._decryption_key = None
        self._notifications = set()

    async def _ensure_connected(self):
        if self.client and self.client.is_connected:
            return

        async with self._connection_lock:
            self.client = await establish_connection(
                self.name, self.get_address, self._async_disconnected
            )
            logger.debug(
                "%s: Connected, processing subscriptions: %s",
                self.name,
                self.subscriptions,
            )
            # The MTU will always be 23 if we do not fetch it
            #
            #  Currently doesn't work, and we need to store it forever since
            #  it will not change
            #
            # if (
            #    self.client.__class__.__name__ == "BleakClientBlueZDBus"
            #    and not self.client._mtu_size
            # ):
            #    try:
            #        await self.client._acquire_mtu()
            #    except (RuntimeError, StopIteration) as ex:
            #        logger.debug("%s: Failed to acquire MTU: %s", ex, address)

    async def _async_start_notify(self, iid: int) -> None:
        if not self._accessories:
            return

        char = self._accessories.aid(1).characteristics.iid(iid)

        # Find the GATT Characteristic object for this iid
        service = self.client.services.get_service(char.service.type)
        endpoint = service.get_characteristic(char.type)

        # We only want to allow one in flight read
        # and one pending read at a time since there
        # may be a notify storm and the read it always
        # going to give us the latest value anyways
        max_callback_enforcer = asyncio.Semaphore(2)

        async def _async_callback() -> None:
            if max_callback_enforcer.locked():
                # Already one being read now, and one pending
                return
            async with max_callback_enforcer:
                if not self.client or not self.client.is_connected:
                    # Client disconnected
                    return
                logger.debug("%s: Retrieving event for iid: %s", self.name, iid)
                results = await self._get_characteristics_while_connected([(1, iid)])
                for listener in self.listeners:
                    listener(results)

        def _callback(id, data) -> None:
            if max_callback_enforcer.locked():
                # Already one being read now, and one pending
                return
            async_create_task(_async_callback())

        logger.debug("%s: Subscribing to iid: %s", self.name, iid)
        await self.client.start_notify(endpoint, _callback)
        self._notifications.add(iid)

    async def _async_pair_verify(self):
        # If resume fails, we are allowed to try again
        # without the previous derive and session_id but
        # that is not yet implemented
        try:
            session_id, derive = await drive_pairing_state_machine(
                self.client,
                CharacteristicsTypes.PAIR_VERIFY,
                get_session_keys(self.pairing_data, self._session_id, self._derive),
            )
        # FIXME: this should not be a broad except handler
        except Exception:  # pylint: disable=broad-except
            logger.debug("%s: Failed to resume, doing full", self.name)
            session_id, derive = await drive_pairing_state_machine(
                self.client,
                CharacteristicsTypes.PAIR_VERIFY,
                get_session_keys(self.pairing_data),
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
        logger.debug(
            "%s: Polling subscriptions for changes during disconnection", self.name
        )
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

                status, _, signature = decode_pdu(tid, payload)
                if status != PDUStatus.SUCCESS:
                    continue

                decoded = CharacteristicTLV.decode(signature).to_dict()

                hap_char = s.add_char(normalize_uuid(char.uuid))
                logger.debug("%s: char: %s decoded: %s", self.name, char, decoded)

                hap_char.iid = iid
                hap_char.perms = decoded["perms"]
                hap_char.format = decoded["format"]

        accessories = Accessories()
        accessories.add_accessory(accessory)

        return accessories

    async def close(self) -> None:
        async with self._connection_lock:
            await self._close_while_locked()

    async def _close_while_locked(self):
        if self.client:
            if not self.client.is_connected:
                return
            try:
                await self.client.disconnect()
            except BleakError:
                logger.debug(
                    "%s: Failed to close connection, client may have already closed it",
                    self.name,
                )
            self.client = None
            self._async_reset_connection_state()
            logger.debug("%s: Connection closed from close call", self.name)

    @retry_bleak_error
    async def list_accessories_and_characteristics(self) -> list[dict[str, Any]]:
        await self._populate_accessories_and_characteristics()
        return self._accessories.serialize()

    async def _populate_char_values(self, config_changed: bool) -> None:
        """Populate the values of all characteristics."""
        for service in self._accessories.aid(1).services:
            if service.type in SKIP_SYNC_SERVICES:
                continue
            if (
                not config_changed
                and service.type == ServicesTypes.ACCESSORY_INFORMATION
            ):
                continue
            for char in service.characteristics:
                if CharacteristicPermissions.paired_read not in char.perms:
                    continue
                aid_iid = (1, char.iid)
                results = await self._get_characteristics_while_connected([aid_iid])
                logger.debug("%s: Read %s", self.address, results)
                if (result := results.get(aid_iid)) and "value" in result:
                    char.value = result["value"]

    async def async_populate_accessories_state(
        self, force_update: bool = False
    ) -> None:
        """Populate the state of all accessories.

        This method should try not to fetch all the accessories unless
        we know the config num is out of date.
        """
        await self._populate_accessories_and_characteristics(force_update)

    async def _populate_accessories_and_characteristics(
        self, force_update: bool = False
    ) -> None:
        was_locked = False
        if self._config_lock.locked():
            was_locked = True
        async with self._config_lock:
            await self._ensure_connected()
            if was_locked:
                # No need to do it twice
                return

            update_values = force_update or not self._accessories
            config_changed = False

            if not self._accessories:
                self._load_accessories_from_cache()

            if not config_changed and self.description:
                config_changed = self._config_num != self.description.config_num

            if not self._accessories or config_changed:
                logger.debug(
                    "%s: Fetching gatt database because, cached_config_num: %s, adv config_num: %s",
                    self.name,
                    self._config_num,
                    self.description.config_num,
                )
                accessories = await self._async_fetch_gatt_database()
                self._accessories_state = AccessoriesState(
                    accessories, self.description.config_num
                )
                update_values = True

            if not self._encryption_key:
                await self._async_pair_verify()

            if update_values:
                await self._populate_char_values(config_changed)
                self._update_accessories_state_cache()

            if config_changed:
                self._callback_and_save_config_changed(self._config_num)

            if not self._notifications and self.subscriptions:
                for _, iid in list(self.subscriptions):
                    if iid not in self._notifications:
                        await self._async_start_notify(iid)

    async def _process_config_changed(self, config_num: int) -> None:
        """Process a config change.

        This method is called when the config num changes.
        """
        await self._populate_accessories_and_characteristics()

    @retry_bleak_error
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

        await self._populate_accessories_and_characteristics()
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

    @retry_bleak_error
    async def get_characteristics(
        self,
        characteristics: list[tuple[int, int]],
    ) -> dict[tuple[int, int], dict[str, Any]]:
        await self._populate_accessories_and_characteristics()
        return await self._get_characteristics_while_connected(characteristics)

    async def _get_characteristics_while_connected(
        self,
        characteristics: list[tuple[int, int]],
    ) -> dict[tuple[int, int], dict[str, Any]]:
        logger.debug("%s: Reading characteristics: %s", self.name, characteristics)

        results = {}

        for aid, iid in characteristics:
            data = await self._async_request(OpCode.CHAR_READ, iid)
            decoded = dict(TLV.decode_bytes(data))[1]

            char = self._accessories.aid(1).characteristics.iid(iid)
            logger.debug(
                "%s: Read characteristic got data, expected format is %s: data=%s decoded=%s",
                self.name,
                char.format,
                data,
                decoded,
            )

            try:
                results[(aid, iid)] = {"value": from_bytes(char, decoded)}
            except struct.error as ex:
                logger.debug(
                    "%s: Failed to decode characteristic for %s from %s: %s",
                    self.name,
                    char,
                    decoded,
                    ex,
                )

        return results

    @retry_bleak_error
    async def put_characteristics(
        self, characteristics: list[tuple[int, int, Any]]
    ) -> dict[tuple[int, int], Any]:
        await self._populate_accessories_and_characteristics()

        results: dict[tuple[int, int], Any] = {}

        for aid, iid, value in characteristics:
            char = self._accessories.aid(1).characteristics.iid(iid)

            if CharacteristicPermissions.timed_write in char.perms:
                payload_inner = TLV.encode_list(
                    [
                        (HAP_TLV.kTLVHAPParamValue, to_bytes(char, value)),
                        (HAP_TLV.kTLVHAPParamTTL, b"\x1e"),  # 3.0s
                    ]
                )
                payload = (len(payload_inner)).to_bytes(
                    length=2, byteorder="little"
                ) + payload_inner
                logger.debug("%s: Timed write payload: %s", self.name, payload)
                response = await self._async_request(
                    OpCode.CHAR_TIMED_WRITE, iid, payload
                )
                decoded = dict(TLV.decode_bytes(response))
                logger.debug("%s: Timed write response: %s", self.name, decoded)
                response = await self._async_request(OpCode.CHAR_EXEC_WRITE, iid)
                decoded = dict(TLV.decode_bytes(response))
                logger.debug("%s: Timed write execute response: %s", self.name, decoded)

            elif CharacteristicPermissions.paired_write in char.perms:
                payload = TLV.encode_list(
                    [(HAP_TLV.kTLVHAPParamValue, to_bytes(char, value))]
                )
                await self._async_request(OpCode.CHAR_WRITE, iid, payload)

            else:
                results[(aid, iid)] = {
                    "status": HapStatusCode.CANT_WRITE_READ_ONLY,
                    "description": HapStatusCode.CANT_WRITE_READ_ONLY.description,
                }

        return results

    async def subscribe(self, characteristics):
        new_chars = await super().subscribe(characteristics)
        if not new_chars:
            return
        logger.debug("%s: subscribing to %s", self.name, new_chars)
        await self._ensure_connected()
        for (aid, iid) in new_chars:
            if iid not in self._notifications:
                await self._async_start_notify(iid)

    async def unsubscribe(self, characteristics):
        pass

    @retry_bleak_error
    async def identify(self):
        await self._populate_accessories_and_characteristics()

        info = self._accessories.aid(1).services.first(
            service_type=ServicesTypes.ACCESSORY_INFORMATION
        )
        char = info[CharacteristicsTypes.IDENTIFY]

        await self.put_characteristics(
            [
                (1, char.iid, True),
            ]
        )

    @retry_bleak_error
    async def add_pairing(
        self, additional_controller_pairing_identifier, ios_device_ltpk, permissions
    ):
        await self._populate_accessories_and_characteristics()
        if permissions == "User":
            permissions = TLV.kTLVType_Permission_RegularUser
        elif permissions == "Admin":
            permissions = TLV.kTLVType_Permission_AdminUser
        else:
            raise RuntimeError(f"{self.name} Unknown permission: {permissions}")

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
            raise InvalidError(
                f"{self.name}: Unexpected state after removing pairing request"
            )

        if TLV.kTLVType_Error in data:
            if data[TLV.kTLVType_Error] == TLV.kTLVError_Authentication:
                raise AuthenticationError(
                    f"{self.name}: Add pairing failed: insufficient access"
                )
            raise UnknownError(f"{self.name}: Add pairing failed: unknown error")

    @retry_bleak_error
    async def remove_pairing(self, pairingId: str):
        await self._populate_accessories_and_characteristics()

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
            raise InvalidError(
                f"{self.name}: Unexpected state after removing pairing request"
            )

        if TLV.kTLVType_Error in data:
            if data[TLV.kTLVType_Error] == TLV.kTLVError_Authentication:
                raise AuthenticationError(
                    f"{self.name}: Remove pairing failed: insufficient access"
                )
            raise UnknownError(f"{self.name}: Remove pairing failed: unknown error")

    async def image(self, accessory: int, width: int, height: int) -> None:
        """Bluetooth devices don't return images."""
        return None
