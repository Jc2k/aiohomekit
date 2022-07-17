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
from collections.abc import Callable
import logging
import random
import struct
from typing import TYPE_CHECKING, Any, TypeVar, cast
import uuid

from bleak.exc import BleakError

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
from .client import (
    AIOHomeKitBleakClient,
    ble_request,
    drive_pairing_state_machine,
    get_characteristic,
    retry_bluetooth_connection_error,
)
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
SUBSCRIPTION_RESTORE_DELAY = 3
SKIP_SYNC_SERVICES = {
    ServicesTypes.THREAD_TRANSPORT,
    ServicesTypes.PAIRING,
    ServicesTypes.TRANSFER_TRANSPORT_MANAGEMENT,
}

WrapFuncType = TypeVar("WrapFuncType", bound=Callable[..., Any])


def operation_lock(func: WrapFuncType) -> WrapFuncType:
    """Define a wrapper to only allow a single operation at a time."""

    async def _async_wrap(self: BlePairing, *args: Any, **kwargs: Any) -> None:
        async with self._operation_lock:
            return await func(self, *args, **kwargs)

    return cast(WrapFuncType, _async_wrap)


class BlePairing(AbstractPairing):
    """
    This represents a paired HomeKit IP accessory.
    """

    def __init__(
        self,
        controller: BleController,
        pairing_data: dict[str, Any],
        client: AIOHomeKitBleakClient | None = None,
        description: HomeKitAdvertisement | None = None,
    ) -> None:
        super().__init__(controller)

        self.id = pairing_data["AccessoryPairingID"]
        self.client = client
        self.pairing_data = pairing_data
        self.description = description
        self.controller = controller

        # Encryption
        self._derive = None
        self._session_id = None
        self._encryption_key: EncryptionKey | None = None
        self._decryption_key: DecryptionKey | None = None

        # Used to keep track of which characteristics we already started
        # notifications for
        self._notifications: set[int] = set()

        # Only allow one attempt to aquire the connection at a time
        self._connection_lock = asyncio.Lock()
        # We don't want to read/write from characteristics in parallel
        # * If 2 coroutines read from the same char at the same time there
        #   would be a race error - a read result could be overwritten by another.
        # * The enc/dec counters are global. Therefore our API's for
        #   a read/write need to be atomic otherwise we end up having
        #   to guess what encryption counter to use for the decrypt
        self._ble_request_lock = asyncio.Lock()
        # Only allow a single operation at at time
        self._operation_lock = asyncio.Lock()
        # Only allow a single attempt to sync config at a time
        self._config_lock = asyncio.Lock()
        # Only subscribe to characteristics one at a time
        self._subscription_lock = asyncio.Lock()

        self._restore_subscriptions_timer: asyncio.TimerHandle | None = None

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
        char = self.accessories.aid(1).characteristics.iid(iid)
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

    def _async_disconnected(self, client: AIOHomeKitBleakClient) -> None:
        """Called when bleak disconnects from the accessory closed the connection."""
        logger.debug("%s: Session closed callback", self.name)
        self._async_reset_connection_state()

    def _async_reset_connection_state(self) -> None:
        """Reset the connection state after a disconnect."""
        self._encryption_key = None
        self._decryption_key = None
        self._notifications = set()
        if self._restore_subscriptions_timer:
            self._restore_subscriptions_timer.cancel()
            self._restore_subscriptions_timer = None

    async def _ensure_connected(self):
        if self.client and self.client.is_connected:
            return
        async with self._connection_lock:
            # Check again while holding the lock
            if self.client and self.client.is_connected:
                return
            self.client = await establish_connection(
                self.client, self.name, self.get_address, self._async_disconnected
            )
            logger.debug(
                "%s: Connected, processing subscriptions: %s",
                self.name,
                self.subscriptions,
            )
            # Only start active subscriptions if we stay connected for more
            # than subscription delay seconds.
            self._restore_subscriptions_timer = asyncio.get_event_loop().call_later(
                SUBSCRIPTION_RESTORE_DELAY, self._restore_subscriptions
            )

    async def _async_start_notify(self, iid: int) -> None:
        char = self.accessories.aid(1).characteristics.iid(iid)

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
                if results := await self._get_characteristics_without_retry([(1, iid)]):
                    for listener in self.listeners:
                        listener(results)

        def _callback(id, data) -> None:
            logger.debug("%s: Received event for iid=%s: %s", self.name, iid, data)
            if data != b"":
                # We should only poll on empty messages, otherwise we may poll
                # the device every second on DBUS systems.
                return
            if max_callback_enforcer.locked():
                # Already one being read now, and one pending
                return
            async_create_task(_async_callback())

        logger.debug("%s: Subscribing to iid: %s", self.name, iid)
        try:
            await self.client.start_notify(endpoint, _callback)
        except ValueError:
            await self.client.stop_notify(endpoint)
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
                    await self.client.write_gatt_char(
                        char.handle,
                        data,
                        "write-without-response" not in char.properties,
                    )

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

    @operation_lock
    @retry_bluetooth_connection_error()
    async def list_accessories_and_characteristics(self) -> list[dict[str, Any]]:
        await self._populate_accessories_and_characteristics()
        return self.accessories.serialize()

    async def _populate_char_values(self, config_changed: bool) -> None:
        """Populate the values of all characteristics."""
        for service in self.accessories.aid(1).services:
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

        Callers should not get BleakError as they expect to trap
        AccessoryDisconnectedError.
        """
        try:
            await self._async_populate_accessories_state(force_update)
        except BleakError as ex:
            raise AccessoryDisconnectedError(f"{self.name} connection failed: {ex}")

    @operation_lock
    @retry_bluetooth_connection_error()
    async def _async_populate_accessories_state(
        self, force_update: bool = False
    ) -> None:
        """Populate the state of all accessories under the lock."""
        await self._populate_accessories_and_characteristics(force_update)

    async def _populate_accessories_and_characteristics(
        self, force_update: bool = False
    ) -> None:
        was_locked = self._config_lock.locked()
        async with self._config_lock:
            await self._ensure_connected()
            if was_locked and not force_update:
                # No need to do it twice if we already have the data
                # and we are not forcing an update
                return

            if not self.accessories:
                self._load_accessories_from_cache()

            update_values = force_update
            config_changed = False
            if self.description:
                config_changed = self.config_num != self.description.config_num

            if not self.accessories or config_changed:
                logger.debug(
                    "%s: Fetching gatt database because, cached_config_num: %s, adv config_num: %s",
                    self.name,
                    self.config_num,
                    self.description.config_num,
                )
                accessories = await self._async_fetch_gatt_database()
                new_config_num = self.description.config_num if self.description else 0
                self._accessories_state = AccessoriesState(accessories, new_config_num)
                update_values = True

            if not self._encryption_key:
                await self._async_pair_verify()

            if update_values:
                await self._populate_char_values(config_changed)
                self._update_accessories_state_cache()

            if config_changed:
                self._callback_and_save_config_changed(self.config_num)

    def _restore_subscriptions(self):
        """Restore subscriptions after after connecting."""
        if self.client and self.client.is_connected:
            async_create_task(
                self._async_start_notify_subscriptions(list(self.subscriptions))
            )

    async def _async_start_notify_subscriptions(
        self, subscriptions: list[tuple[int, int]]
    ) -> None:
        """Start notifications for the given subscriptions."""
        if not self.accessories or not self.client.is_connected:
            return

        for _, iid in subscriptions:
            if iid in self._notifications:
                continue
            # The iid will not be in in self._notifications until
            # the _async_start_notify call returns.
            async with self._subscription_lock:
                if iid not in self._notifications and self.client.is_connected:
                    await self._async_start_notify(iid)

    @operation_lock
    @retry_bluetooth_connection_error()
    async def _process_config_changed(self, config_num: int) -> None:
        """Process a config change.

        This method is called when the config num changes.
        """
        await self._populate_accessories_and_characteristics()

    @operation_lock
    @retry_bluetooth_connection_error()
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

        info = self.accessories.aid(1).services.first(
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

    @retry_bluetooth_connection_error()
    async def get_characteristics(
        self,
        characteristics: list[tuple[int, int]],
    ) -> dict[tuple[int, int], dict[str, Any]]:
        return await self._get_characteristics_without_retry(characteristics)

    @operation_lock
    async def _get_characteristics_without_retry(
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

            char = self.accessories.aid(1).characteristics.iid(iid)
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

    @operation_lock
    @retry_bluetooth_connection_error()
    async def put_characteristics(
        self, characteristics: list[tuple[int, int, Any]]
    ) -> dict[tuple[int, int], Any]:
        await self._populate_accessories_and_characteristics()

        results: dict[tuple[int, int], Any] = {}

        for aid, iid, value in characteristics:
            char = self.accessories.aid(1).characteristics.iid(iid)

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
                await self._async_request(OpCode.CHAR_TIMED_WRITE, iid, payload)
                await self._async_request(OpCode.CHAR_EXEC_WRITE, iid)

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

    # No retry since disconnected events are ok as well
    @operation_lock
    async def subscribe(self, characteristics):
        new_chars = await super().subscribe(characteristics)
        if not new_chars:
            return
        logger.debug("%s: subscribing to %s", self.name, new_chars)
        await self._populate_accessories_and_characteristics()
        await self._async_start_notify_subscriptions(new_chars)

    async def unsubscribe(self, characteristics):
        pass

    @operation_lock
    @retry_bluetooth_connection_error()
    async def identify(self):
        await self._populate_accessories_and_characteristics()

        info = self.accessories.aid(1).services.first(
            service_type=ServicesTypes.ACCESSORY_INFORMATION
        )
        char = info[CharacteristicsTypes.IDENTIFY]

        await self.put_characteristics(
            [
                (1, char.iid, True),
            ]
        )

    @operation_lock
    @retry_bluetooth_connection_error()
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

        info = self.accessories.aid(1).services.first(
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

    @operation_lock
    @retry_bluetooth_connection_error(attempts=10)
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

        info = self.accessories.aid(1).services.first(
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
