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
from collections.abc import Callable, Iterable
from datetime import timedelta
import logging
import random
import struct
import time
from typing import TYPE_CHECKING, Any, TypeVar, cast
from uuid import UUID

from bleak.backends.characteristic import BleakGATTCharacteristic
from bleak.backends.device import BLEDevice
from bleak.backends.scanner import AdvertisementData
from bleak.exc import BleakError
from bleak_retry_connector import (
    BLEAK_RETRY_EXCEPTIONS as BLEAK_EXCEPTIONS,
    retry_bluetooth_connection_error,
)

from aiohomekit.exceptions import (
    AccessoryDisconnectedError,
    AccessoryNotFoundError,
    AuthenticationError,
    InvalidError,
    UnknownError,
)
from aiohomekit.meshcop import Meshcop
from aiohomekit.model import (
    Accessories,
    AccessoriesState,
    Accessory,
    CharacteristicsTypes,
    Transport,
)
from aiohomekit.model.characteristics import Characteristic, CharacteristicPermissions
from aiohomekit.model.services import Service, ServicesTypes
from aiohomekit.pdu import OpCode, PDUStatus, decode_pdu, encode_pdu
from aiohomekit.protocol import get_session_keys
from aiohomekit.protocol.statuscodes import HapStatusCode
from aiohomekit.protocol.tlv import TLV
from aiohomekit.utils import async_create_task
from aiohomekit.uuid import normalize_uuid

from ..abstract import AbstractPairing, AbstractPairingData
from .bleak import AIOHomeKitBleakClient
from .client import (
    PDUStatusError,
    ble_request,
    disconnect_on_missing_services,
    drive_pairing_state_machine,
    raise_for_pdu_status,
)
from .connection import establish_connection
from .key import BroadcastDecryptionKey, DecryptionKey, EncryptionKey
from .manufacturer_data import HomeKitAdvertisement, HomeKitEncryptedNotification
from .structs import (
    HAP_BLE_CHARACTERISTIC_CONFIGURATION_REQUEST_TLV,
    HAP_BLE_PROTOCOL_CONFIGURATION_REQUEST_TLV,
    HAP_TLV,
    Characteristic as CharacteristicTLV,
    ProtocolParams,
    ProtocolParamsTLV,
    Service as ServiceTLV,
)
from .values import from_bytes, to_bytes

if TYPE_CHECKING:
    from aiohomekit.controller.ble.controller import BleController

logger = logging.getLogger(__name__)

# The discover timeout is how long we will wait for and advertisement to be
# received. If we don't get it in this time we will try again later since
# the scanner is always running anyways.
DISCOVER_TIMEOUT = 10

# Battery powered devices may not broadcast once paired until
# there is an event so we use a long availablity interval.
AVAILABILITY_INTERVAL = 86400 * 7  # 7 days

NEVER_TIME = -AVAILABILITY_INTERVAL

START_NOTIFY_DEBOUNCE = 1.5
MAX_GSN = 65535

SERVICE_INSTANCE_ID = "E604E95D-A759-4817-87D3-AA005083A0D1"
SERVICE_INSTANCE_ID_UUID = UUID(SERVICE_INSTANCE_ID)

SERVICE_SIGNATURE_UUID = UUID(CharacteristicsTypes.SERVICE_SIGNATURE)

SKIP_SYNC_SERVICES = {
    ServicesTypes.PAIRING,
    ServicesTypes.TRANSFER_TRANSPORT_MANAGEMENT,
}
# These characteristics are not readable unless there has been a write
WRITE_FIRST_REQUIRED_CHARACTERISTICS = {
    CharacteristicsTypes.SETUP_DATA_STREAM_TRANSPORT,  # Setup Data Stream Transport
    CharacteristicsTypes.SELECTED_RTP_STREAM_CONFIGURATION,  # Selected RTP Stream Configuration
    CharacteristicsTypes.SETUP_ENDPOINTS,  # Setup Endpoints
    "00000138-0000-1000-8000-0026BB765291",  # Unknown write first characteristic
    "246912DC-8FA3-82ED-DEA4-9EB91D8FC2EE",  # Unknown Vendor char seen on Belkin Wemo Switch
}
IGNORE_READ_CHARACTERISTICS = {
    CharacteristicsTypes.SERVICE_SIGNATURE
} | WRITE_FIRST_REQUIRED_CHARACTERISTICS
BLE_AID = 1  # The aid for BLE devices is always 1

ENABLE_BROADCAST_PAYLOAD = TLV.encode_list(
    [
        (
            HAP_BLE_CHARACTERISTIC_CONFIGURATION_REQUEST_TLV.kTLVHAPParamCharacteristicConfigurationProperties,
            int.to_bytes(1, 2, "little"),
        ),
        (
            HAP_BLE_CHARACTERISTIC_CONFIGURATION_REQUEST_TLV.kTLVHAPParamCharacteristicConfigurationBroadcastInterval,
            bytes([0x01]),
        ),
    ]
)

GENERATE_BROADCAST_KEY_PAYLOAD = (
    bytes([HAP_BLE_PROTOCOL_CONFIGURATION_REQUEST_TLV.GenerateBroadcastEncryptionKey])
    + b"\x00"
)

GET_ALL_PARAMS_PAYLOAD = (
    bytes([HAP_BLE_PROTOCOL_CONFIGURATION_REQUEST_TLV.GetAllParams]) + b"\x00"
)

# Higher priority means we will fetch these first
CHAR_FETCH_PRIORITY = {
    CharacteristicsTypes.MOTION_DETECTED: 100,
    CharacteristicsTypes.CONTACT_STATE: 100,
    CharacteristicsTypes.OCCUPANCY_DETECTED: 100,
    CharacteristicsTypes.DOOR_STATE_CURRENT: 100,
    CharacteristicsTypes.DOOR_STATE_TARGET: 100,
    CharacteristicsTypes.INPUT_EVENT: 100,
    CharacteristicsTypes.ON: 100,
    CharacteristicsTypes.ACTIVE: 100,
    CharacteristicsTypes.LOCK_MECHANISM_CURRENT_STATE: 100,
    CharacteristicsTypes.LOCK_MECHANISM_TARGET_STATE: 100,
    CharacteristicsTypes.LEAK_DETECTED: 90,
    CharacteristicsTypes.SMOKE_DETECTED: 90,
    CharacteristicsTypes.CARBON_MONOXIDE_DETECTED: 90,
    CharacteristicsTypes.CARBON_DIOXIDE_DETECTED: 90,
    CharacteristicsTypes.BRIGHTNESS: 90,
    CharacteristicsTypes.HUE: 90,
    CharacteristicsTypes.SATURATION: 90,
    CharacteristicsTypes.COLOR_TEMPERATURE: 90,
    CharacteristicsTypes.VERSION: -50,
    CharacteristicsTypes.NAME: -50,
    CharacteristicsTypes.THREAD_CONTROL_POINT: -100,
    CharacteristicsTypes.THREAD_STATUS: -100,
    CharacteristicsTypes.THREAD_NODE_CAPABILITIES: -100,
    CharacteristicsTypes.THREAD_OPENTHREAD_VERSION: -100,
}

WrapFuncType = TypeVar("WrapFuncType", bound=Callable[..., Any])


def operation_lock(func: WrapFuncType) -> WrapFuncType:
    """Define a wrapper to only allow a single operation at a time."""

    async def _async_operation_lock_wrap(
        self: BlePairing, *args: Any, **kwargs: Any
    ) -> None:
        async with self._operation_lock:
            return await func(self, *args, **kwargs)

    return cast(WrapFuncType, _async_operation_lock_wrap)


def restore_connection_and_resume(func: WrapFuncType) -> WrapFuncType:
    """Define a wrapper restore connection, populate data, and then resume when the operation completes."""

    async def _async_restore_and_resume(
        self: BlePairing, *args: Any, **kwargs: Any
    ) -> None:
        """Restore connection, populate data, and then resume when the operation completes."""
        if self._shutdown:
            return
        await self._populate_accessories_and_characteristics()
        try:
            return await func(self, *args, **kwargs)
        finally:
            logger.debug(
                "%s: Finished %s, checking for subscription restore: %s",
                self.name,
                func.__name__,
                self._restore_pending,
            )
            if not self._shutdown and self._restore_pending:
                await self._async_restore_subscriptions()

    return cast(WrapFuncType, _async_restore_and_resume)


def force_fresh_connection(func: WrapFuncType) -> WrapFuncType:
    """Define a wrapper to force a fresh connection."""

    async def _async_force_fresh_connection(
        self: BlePairing, *args: Any, **kwargs: Any
    ) -> None:
        """Force a fresh connection."""
        if self.client:
            await self.client.disconnect()
        return await func(self, *args, **kwargs)

    return cast(WrapFuncType, _async_force_fresh_connection)


class BlePairing(AbstractPairing):
    """
    This represents a paired HomeKit IP accessory.
    """

    description: HomeKitAdvertisement
    controller: BleController

    def __init__(
        self,
        controller: BleController,
        pairing_data: AbstractPairingData,
        device: BLEDevice | None = None,
        client: AIOHomeKitBleakClient | None = None,
        description: HomeKitAdvertisement | None = None,
        ble_advertisement: AdvertisementData | None = None,
    ) -> None:
        self.device = device
        self.ble_advertisement = ble_advertisement
        self.client = client
        self.description = description
        self.pairing_data = pairing_data

        super().__init__(controller, pairing_data)

        self._last_seen = time.monotonic() if description else NEVER_TIME

        if not description and self.state_num:
            self.description = HomeKitAdvertisement.from_cache(
                address=self.address,
                id=self.id,
                config_num=self.config_num,
                state_num=self.state_num,
            )

        # Encryption
        self._derive = None
        self._session_id = None
        self._encryption_key: EncryptionKey | None = None
        self._decryption_key: DecryptionKey | None = None
        self._broadcast_decryption_key: BroadcastDecryptionKey | None = None

        cached_key = self.broadcast_key
        if cached_key:
            self._broadcast_decryption_key = BroadcastDecryptionKey(cached_key)

        # Used to keep track of which characteristics we already started
        # notifications for
        self._notifications: set[int] = set()
        self._broadcast_notifications: set[int] = set()

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
        # Only process disconnected events once
        self._disconnected_events_lock = asyncio.Lock()

        self._start_notify_timer: asyncio.TimerHandle | None = None

        self._tried_to_connect_once = False
        self._restore_pending = False
        self._fetched_gsn_this_session = False
        self._had_notify_this_session = False

    @property
    def address(self) -> str:
        """Return the address of the device."""
        return (
            self.device.address
            if self.device
            else self.pairing_data["AccessoryAddress"]
        )

    @property
    def name(self) -> str:
        """Return the name of the pairing with the address."""
        if self.description:
            return f"{self.description.name} [{self.address}] (id={self.id})"
        return f"[{self.address}] (id={self.id})"

    @property
    def rssi(self) -> int | None:
        return self.ble_advertisement.rssi if self.ble_advertisement else None

    @property
    def is_connected(self) -> bool:
        return bool(self.client and self.client.is_connected and self._encryption_key)

    @property
    def is_available(self) -> bool:
        """Returns true if the device is currently available."""
        return self._is_available_at_time(time.monotonic())

    @property
    def poll_interval(self) -> timedelta:
        """Returns how often the device should be polled."""
        if any(a.needs_polling for a in self.accessories):
            # Currently only used for devices that have energy data
            return timedelta(minutes=5)
        return timedelta(hours=24)

    def _is_available_at_time(self, monotonic: float) -> bool:
        """Check if we are considered available at the given time."""
        return self.is_connected or monotonic - self._last_seen < AVAILABILITY_INTERVAL

    @property
    def transport(self) -> Transport:
        """The transport used for the connection."""
        return Transport.BLE

    def _update_state_num(self, state_num: int) -> None:
        """Update the state number."""
        self.description.state_num = state_num
        self._update_cached_state_num(state_num)

    def _update_cached_state_num(self, state_num: int) -> None:
        """Update the cached state number which is restored between restarts."""
        old_state_num = self._accessories_state.state_num
        self._accessories_state.state_num = state_num
        if old_state_num != state_num:
            self._update_accessories_state_cache()

    def _async_ble_update(
        self, device: BLEDevice, ble_advertisement: AdvertisementData
    ) -> None:
        """Update the BLE device and ble_advertisement."""
        self.device = device
        self.ble_advertisement = ble_advertisement

    def _async_description_update(
        self, description: HomeKitAdvertisement | None
    ) -> None:
        """Update the description of the accessory."""
        now = time.monotonic()
        was_available = self._is_available_at_time(now)
        self._last_seen = now
        if not was_available:
            self._callback_availability_changed(True)
        if self.description != description:
            logger.debug(
                "%s: Description updated: old=%s new=%s",
                self.name,
                self.description,
                description,
            )

        super()._async_description_update(description)
        self._update_cached_state_num(description.state_num)

    async def _async_request(
        self,
        opcode: OpCode,
        char: Characteristic,
        data: bytes | None = None,
        iid: int | None = None,
    ) -> bytes:
        async with self._ble_request_lock:
            return await self._async_request_under_lock(opcode, char, data, iid)

    async def _async_request_under_lock(
        self,
        opcode: OpCode,
        char: Characteristic,
        data: bytes | None = None,
        iid: int | None = None,
    ) -> bytes:
        assert self._ble_request_lock.locked(), "_ble_request_lock Should be locked"
        if not self.client or not self.client.is_connected:
            logger.debug("%s: Client not connected; rssi=%s", self.name, self.rssi)
            raise AccessoryDisconnectedError(f"{self.name} is not connected")

        endpoint_iid = iid if iid is not None else char.iid
        endpoint = await self.client.get_characteristic(
            char.service.type, char.type, endpoint_iid
        )

        pdu_status, result_data = await ble_request(
            self.client,
            self._encryption_key,
            self._decryption_key,
            opcode,
            endpoint,
            endpoint_iid,
            data,
        )

        if not self.client or not self.client.is_connected:
            logger.debug("%s: Client not connected; rssi=%s", self.name, self.rssi)
            raise AccessoryDisconnectedError(f"{self.name} is not connected")

        raise_for_pdu_status(self.client, pdu_status)
        return result_data

    def _async_disconnected(self, client: AIOHomeKitBleakClient) -> None:
        """Called when bleak disconnects from the accessory closed the connection."""
        logger.debug("%s: Session closed callback: rssi=%s", self.name, self.rssi)
        self._async_reset_connection_state()

    def _async_reset_connection_state(self) -> None:
        """Reset the connection state after a disconnect."""
        self._encryption_key = None
        self._decryption_key = None
        self._notifications = set()
        self._broadcast_notifications = set()
        self._restore_pending = False
        self._fetched_gsn_this_session = False
        self._had_notify_this_session = False

    async def _ensure_connected(self, attempts: int | None = None) -> bool | None:
        """Ensure that we are connected to the accessory.

        Returns True if we had to make the connection,
        returns False if we were already connected or shutdown.
        """
        assert self._config_lock.locked(), "_config_lock Should be locked"
        if self._shutdown or (self.client and self.client.is_connected):
            return False
        async with self._connection_lock:
            # Check again while holding the lock
            if self._shutdown or (self.client and self.client.is_connected):
                return False
            if not self.device and (
                discovery := await self.controller.async_find(self.id, DISCOVER_TIMEOUT)
            ):
                self.device = discovery.device
                self.ble_advertisement = discovery.ble_advertisement
                self.description = discovery.description
            elif not self.device:
                raise AccessoryNotFoundError(f"{self.name}: Could not find {self.id}")
            self.client = await establish_connection(
                self.device,
                self.name,
                self._async_disconnected,
                use_services_cache=True,
                ble_device_callback=lambda: self.device,
                max_attempts=attempts,
            )
            return True

    async def _async_start_notify(self, iid: int) -> None:
        assert self._operation_lock.locked(), "_operation_lock should be locked"
        char = self.accessories.aid(BLE_AID).characteristics.iid(iid)

        # Find the GATT Characteristic object for this iid
        endpoint = await self.client.get_characteristic(
            char.service.type, char.type, iid
        )

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
                async with self._operation_lock:
                    logger.debug("%s: Retrieving event for iid: %s", self.name, iid)
                    await self._get_characteristics_while_connected(
                        [char], notify_listeners=True
                    )
                    # The GSN value is always the same per session.
                    # It will never increment until the session is closed.
                    #
                    # If we haven't fetched the GSN this session, do it now.
                    if not self._fetched_gsn_this_session and (
                        protocol_param := await self._get_all_protocol_params()
                    ):
                        self._update_state_num(protocol_param.state_number)

                    if not self._had_notify_this_session:
                        self._had_notify_this_session = True
                        # 7.4.1.8 Global State Number (GSN)
                        # The GSN is only increased once per session
                        # so we only want to increase it if we have
                        # not already done so this session.
                        #
                        # The fetched GSN from _get_all_protocol_params
                        # is NOT increased when we get a notify so we need
                        # to do it here.
                        #
                        new_state_num = self.description.state_num + 1
                        if new_state_num >= MAX_GSN:
                            new_state_num = 1
                            # GSN rolled over which invalidates the broadcast
                            # encryption key. We need to re-fetch it.
                            await self._async_set_broadcast_encryption_key()
                        self._update_state_num(new_state_num)

        def _callback(id: int, data: bytes) -> None:
            logger.debug("%s: Received event for iid=%s: %s", self.name, iid, data)
            if data != b"":
                # We should only poll on empty messages, otherwise we may poll
                # the device every second on DBUS systems.
                return
            if max_callback_enforcer.locked():
                # Already one being read now, and one pending
                return
            async_create_task(_async_callback())

        logger.debug("%s: Subscribing to gatt notify for iid: %s", self.name, iid)
        await self.client.start_notify(endpoint, _callback)
        self._notifications.add(iid)

    async def _async_pair_verify(self) -> None:
        async with self._ble_request_lock:
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

    async def _process_disconnected_events(self) -> None:
        """Handle disconnected events seen from the advertisement."""
        if not self._tried_to_connect_once:
            # We never tried connected to the accessory, so we don't need to
            # process the disconnected events
            logger.debug(
                "%s: Skipping disconnected events because we have not yet connected.",
                self.name,
            )
            return

        if self._disconnected_events_lock.locked():
            # Already processing disconnected events
            return

        async with self._disconnected_events_lock:
            logger.debug(
                "%s: Polling subscriptions for changes during disconnection; rssi=%s",
                self.name,
                self.rssi,
            )
            try:
                protocol_param = await self._process_disconnected_events_with_retry()
            except (
                AccessoryDisconnectedError,
                *BLEAK_EXCEPTIONS,
                AccessoryNotFoundError,
            ) as exc:
                logger.exception(
                    "%s: Failed to fetch disconnected events: %s; rssi=%s",
                    self.name,
                    exc,
                    self.rssi,
                )
                return

            if protocol_param:
                self._update_state_num(protocol_param.state_number)

    @operation_lock
    @retry_bluetooth_connection_error()
    @disconnect_on_missing_services
    @restore_connection_and_resume
    async def _process_disconnected_events_with_retry(
        self,
    ) -> ProtocolParams | None:
        accessory_chars = self.accessories.aid(BLE_AID).characteristics
        protocol_param = await self._get_all_protocol_params()
        chars_to_update = []
        for _, iid in self.subscriptions:
            char = accessory_chars.iid(iid)
            if char.broadcast_events or char.disconnected_events:
                chars_to_update.append(char)
        if chars_to_update:
            await self._get_characteristics_while_connected(
                chars_to_update,
                notify_listeners=True,
            )
        return protocol_param

    def _async_notification(self, data: HomeKitEncryptedNotification) -> None:
        """Receive a notification from the accessory."""
        if not self._broadcast_decryption_key:
            logger.debug(
                "%s: Received notification before session is setup, "
                "falling back processing as disconnected event: %s",
                self.name,
                data,
            )
            async_create_task(self._process_disconnected_events())
            return

        if not self.description:
            logger.error(
                "%s: Received encrypted notification before advertisement.",
                self.name,
            )
            return

        start_state_num = self.description.state_num
        # Usually we increment by one, but sometimes we get multiple with the same
        # state number so the first pass is optimistic to reduce the number of
        # of decrypts we do.
        for state_num in (
            start_state_num + 1,
            start_state_num,
            *range(start_state_num + 2, start_state_num + 100),
        ):
            logger.debug(
                "%s: Trying state_num %s for encrypted notification: %s",
                self.name,
                state_num,
                data,
            )
            decrypted = self._broadcast_decryption_key.decrypt(
                data.encrypted_payload,
                state_num,
                data.advertising_identifier,
            )
            if decrypted is None:
                continue
            gsn = int.from_bytes(decrypted[0:2], "little")
            if gsn != state_num:
                logger.debug(
                    "%s: GSN mismatch, expected: %s, got: %s",
                    self.name,
                    state_num,
                    gsn,
                )
                return
            iid = int.from_bytes(decrypted[2:4], "little")
            value = decrypted[4:12]
            logger.debug(
                "%s: Received notification: encrypted =  %s - decrypted = %s - gsn=%s - iid=%s - value=%s",
                self.name,
                data.encrypted_payload,
                decrypted,
                gsn,
                iid,
                value,
            )
            # We had a successful decrypt, so we can update the state_num
            self.description.state_num = gsn
            char = self.accessories.aid(BLE_AID).characteristics.iid(iid)

            results = {(BLE_AID, iid): {"value": from_bytes(char, value)}}
            logger.debug("%s: Received notification: results = %s", self.name, results)

            self._callback_listeners(results)
            return

        logger.warning(
            "%s: Received notification but could not decrypt, falling back processing as disconnected event: %s",
            self.name,
            data,
        )
        async_create_task(self._process_disconnected_events())

    def _async_get_service_signature_char(self) -> Characteristic | None:
        """Get the service signature characteristic."""
        info = self.accessories.aid(BLE_AID).services.first(
            service_type=ServicesTypes.PROTOCOL_INFORMATION
        )
        if not info:
            logger.debug("%s: No signature service found", self.name)
            return None
        if not info.has(CharacteristicsTypes.SERVICE_SIGNATURE):
            logger.debug(
                "%s: No signature characteristic found, "
                "accessory may not implement encrypted notifications",
                self.name,
            )
            return None
        return info[CharacteristicsTypes.SERVICE_SIGNATURE]

    async def _async_set_broadcast_encryption_key(self) -> None:
        """Get the broadcast key for the accessory."""
        assert self._operation_lock.locked(), "_operation_lock should be locked"
        logger.debug("%s: Setting broadcast encryption key", self.name)
        if self._ble_request_lock.locked():
            logger.debug(
                "%s: Waiting ble request lock to set broadcast encryption key",
                self.name,
            )
        async with self._ble_request_lock:
            hap_char = self._async_get_service_signature_char()
            if not hap_char:
                return
            service_iid = hap_char.service.iid
            logger.debug(
                "%s: Setting broadcast key for service_iid: %s",
                self.name,
                service_iid,
            )
            try:
                await self._async_request_under_lock(
                    OpCode.PROTOCOL_CONFIG,
                    hap_char,
                    GENERATE_BROADCAST_KEY_PAYLOAD,
                    iid=service_iid,
                )
            except PDUStatusError:
                logger.exception(
                    "%s: Failed to set broadcast key, try un-paring and re-pairing the accessory.",
                    self.name,
                )
        long_term_pub_key_hex: str = self.pairing_data["iOSDeviceLTPK"]
        long_term_pub_key_bytes = bytes.fromhex(long_term_pub_key_hex)
        broadcast_key_bytes = self._derive(
            long_term_pub_key_bytes, b"Broadcast-Encryption-Key"
        )
        self._broadcast_decryption_key = BroadcastDecryptionKey(broadcast_key_bytes)
        if self._accessories_state and self.broadcast_key != broadcast_key_bytes:
            self._accessories_state.broadcast_key = broadcast_key_bytes
            self._callback_and_save_config_changed(self.config_num)

    async def _read_signature(
        self,
        char: BleakGATTCharacteristic,
        op_code: OpCode,
        iid: int,
        tlv_struct: ServiceTLV | CharacteristicTLV,
    ) -> dict[str, Any]:
        """Read the signature for the given characteristic."""
        tid = random.randint(1, 254)
        for data in encode_pdu(op_code, tid, iid):
            await self.client.write_gatt_char(
                char,
                data,
                "write-without-response" not in char.properties,
            )

        payload = await self.client.read_gatt_char(char)

        status, _, signature = decode_pdu(tid, payload)
        if status != PDUStatus.SUCCESS:
            return {}

        return tlv_struct.decode(signature).to_dict()

    async def _async_fetch_gatt_database(self) -> Accessories:
        logger.debug("%s: Fetching GATT database; rssi=%s", self.name, self.rssi)
        accessory = Accessory()
        accessory.aid = 1
        # Never use the cache when fetching the GATT database
        services_to_link: list[tuple[Service, list[int]]] = []
        services = self.client.services
        for service in services:
            ble_service_char = service.get_characteristic(SERVICE_INSTANCE_ID_UUID)
            if not ble_service_char:
                logger.debug(
                    "%s: Skipping service without service instance id: %s",
                    self.name,
                    service,
                )
                continue

            service_iid_bytes = await self.client.read_gatt_char(
                ble_service_char.handle
            )
            service_iid = int.from_bytes(service_iid_bytes, "little")
            logger.debug(
                "%s: Service %s iid: %s (decoded as %s)",
                self.name,
                service.uuid,
                service_iid_bytes,
                service_iid,
            )
            s = accessory.add_service(normalize_uuid(service.uuid), iid=service_iid)

            service_signature_char = service.get_characteristic(SERVICE_SIGNATURE_UUID)
            if service_signature_char:
                decoded_service = await self._read_signature(
                    service_signature_char,
                    OpCode.SERV_SIG_READ,
                    service_iid,
                    ServiceTLV,
                )
                if "linked" in decoded_service:
                    services_to_link.append((s, decoded_service["linked"]))
                logger.debug(
                    "%s: service: %s decoded: %s", self.name, service, decoded_service
                )

            for char in service.characteristics:
                normalized_uuid = normalize_uuid(char.uuid)
                if normalized_uuid == SERVICE_INSTANCE_ID:
                    continue

                iid = await self.client.get_characteristic_iid(char)
                if iid is None:
                    logger.debug("%s: No iid for %s", self.name, char.uuid)
                    continue

                decoded = await self._read_signature(
                    char, OpCode.CHAR_SIG_READ, iid, CharacteristicTLV
                )
                if normalized_uuid == CharacteristicsTypes.IDENTIFY:
                    # Workaround for older eve v1 devices which has a broken identify characteristic
                    # that presents identify as data.
                    decoded["format"] = "bool"

                hap_char = s.add_char(normalized_uuid, iid=iid)
                logger.debug("%s: char: %s decoded: %s", self.name, char, decoded)
                assert hap_char.iid == iid, "iid should be set"
                hap_char.handle = char.handle
                hap_char.perms = decoded["perms"]
                # Some vendor characteristics have no format
                # See https://github.com/home-assistant/core/issues/76104
                if "format" in decoded:
                    hap_char.format = decoded["format"]
                if "minStep" in decoded:
                    hap_char.minStep = decoded["minStep"]
                if "minValue" in decoded:
                    hap_char.minValue = decoded["minValue"]
                if "maxValue" in decoded:
                    hap_char.maxValue = decoded["maxValue"]
                if "disconnected_events" in decoded:
                    hap_char.disconnected_events = decoded["disconnected_events"]
                if "broadcast_events" in decoded:
                    hap_char.broadcast_events = decoded["broadcast_events"]

        # Link services after we are done since we need to have all services
        # in the accessory to link them.
        for service, linked in services_to_link:
            for iid in linked:
                service.add_linked_service(accessory.services.iid(iid))

        accessories = Accessories()
        accessories.add_accessory(accessory)
        logger.debug("%s: Completed fetching GATT database", self.name)

        return accessories

    @operation_lock
    async def close_after_operation(self) -> None:
        """Close the client after an operation."""
        await self.close()

    async def close(self) -> None:
        async with self._connection_lock:
            await self._close_while_locked()

    async def _close_while_locked(self) -> None:
        if not self.client or not self.client.is_connected:
            return
        try:
            await self.client.disconnect()
        except BleakError:
            logger.debug(
                "%s: Failed to close connection, client may have already closed it; rssi=%s",
                self.name,
                self.rssi,
            )
        self.client = None
        self._async_reset_connection_state()
        logger.debug(
            "%s: Connection closed from close call; rssi=%s", self.name, self.rssi
        )

    @operation_lock
    @retry_bluetooth_connection_error()
    @disconnect_on_missing_services
    @restore_connection_and_resume
    async def list_accessories_and_characteristics(self) -> list[dict[str, Any]]:
        return self.accessories.serialize()

    async def get_primary_name(self) -> str:
        """Return the primary name of the device.

        This overrides the default implementation
        to get name from the advertisement if the
        accessories are not available which happens
        frequently with the ESPHome proxies because
        they cannot currently connect right away again
        after disconnecting.

        We want to avoid raising here if possible
        since this is called right after pairing
        and if we raise the pairing will fail but
        the device will still be paired and the user
        will have to un-pair it manually with a factory
        reset.
        """
        if not self.accessories and self.description:
            self._accessories_state = AccessoriesState(
                Accessories(), -1, self.broadcast_key, self.state_num
            )
            return self.description.name
        return await super().get_primary_name()

    async def _populate_char_values(self, config_changed: bool) -> None:
        """Populate the values of all characteristics."""
        chars: list[Characteristic] = []
        for service in self.accessories.aid(BLE_AID).services:
            if service.type in SKIP_SYNC_SERVICES:
                continue
            if (
                not config_changed
                and service.type == ServicesTypes.ACCESSORY_INFORMATION
                and service.value(CharacteristicsTypes.NAME)
            ):
                continue
            for char in service.characteristics:
                if char.type in IGNORE_READ_CHARACTERISTICS:
                    continue
                if CharacteristicPermissions.paired_read not in char.perms:
                    continue
                chars.append(char)

        if not chars:
            return

        protocol_params = await self._get_all_protocol_params()

        results = await self._get_characteristics_while_connected(chars)
        logger.debug("%s: Read %s", self.name, results)
        for char in chars:
            result = results.get((BLE_AID, char.iid))
            if not result or "value" not in result:
                logger.debug(
                    "%s: No value for %s/%s", self.name, char.service.type, char.type
                )
                continue
            char.value = result["value"]

        if protocol_params:
            self.description.state_num = protocol_params.state_number

    async def _get_all_protocol_params(self) -> ProtocolParams | None:
        """Get the current protocol params number."""
        assert self._operation_lock.locked(), "_operation_lock should be locked"
        hap_char = self._async_get_service_signature_char()
        if not hap_char:
            return
        service_iid = hap_char.service.iid
        try:
            resp = await self._async_request(
                OpCode.PROTOCOL_CONFIG,
                hap_char,
                GET_ALL_PARAMS_PAYLOAD,
                iid=service_iid,
            )
        except PDUStatusError:
            logger.exception(
                "%s: Failed to get global state number.",
                self.name,
            )
            return None
        response = dict(TLV.decode_bytes(resp))
        protocol_params = ProtocolParams(
            state_number=int.from_bytes(
                response[ProtocolParamsTLV.GlobalStateNumber], "little"
            ),
            config_number=int.from_bytes(
                response[ProtocolParamsTLV.ConfigurationNumber], "little"
            ),
            advertising_id=response[ProtocolParamsTLV.AdvertisingId],
            broadcast_key=response.get(ProtocolParamsTLV.BroadcastKey),
        )
        logger.debug(
            "%s: Fetched protocol params: gsn=%s, c#=%s",
            self.name,
            protocol_params.state_number,
            protocol_params.config_number,
        )
        self._fetched_gsn_this_session = True
        return protocol_params

    async def async_populate_accessories_state(
        self, force_update: bool = False, attempts: int | None = None
    ) -> None:
        """Populate the state of all accessories.

        This method should try not to fetch all the accessories unless
        we know the config num is out of date.

        Callers should not get BleakError as they expect to trap
        AccessoryDisconnectedError.
        """
        try:
            await self._async_populate_accessories_state(force_update, attempts)
        except BleakError as ex:
            raise AccessoryDisconnectedError(
                f"{self.name} connection failed: {ex}; rssi={self.rssi}"
            ) from ex

    @operation_lock
    @retry_bluetooth_connection_error()
    @disconnect_on_missing_services
    async def _async_populate_accessories_state(
        self, force_update: bool = False, attempts: int | None = None
    ) -> None:
        """Populate the state of all accessories under the lock."""
        await self._populate_accessories_and_characteristics(force_update, attempts)
        if self._restore_pending:
            await self._async_restore_subscriptions()

    async def _populate_accessories_and_characteristics(
        self, force_update: bool = False, attempts: int | None = None
    ) -> None:
        was_locked = self._config_lock.locked()
        async with self._config_lock:
            if self._shutdown:
                return

            try:
                made_connection = await self._ensure_connected(attempts)
            finally:
                # Only set _tried_to_connect_once after the connection
                # attempt is complete so we don't try to process disconnected
                # events while we are still trying to connect.
                self._tried_to_connect_once = True

            logger.debug(
                "%s: Populating accessories and characteristics: made_connection=%s restore_pending=%s",
                self.name,
                made_connection,
                self._restore_pending,
            )
            self._restore_pending |= made_connection

            if was_locked and not force_update:
                # No need to do it twice if we already have the data
                # and we are not forcing an update
                return

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
                self._accessories_state = AccessoriesState(
                    accessories, new_config_num, self.broadcast_key
                )
                update_values = True

            if not self._encryption_key:
                await self._async_pair_verify()

            if update_values:
                await self._populate_char_values(config_changed)
                self._update_accessories_state_cache()

            if config_changed:
                self._callback_and_save_config_changed(self.config_num)

    async def _async_subscribe_broadcast_events(
        self, subscriptions: list[tuple[int, int]]
    ) -> None:
        """Subscribe to broadcast events."""
        accessory_chars = self.accessories.aid(BLE_AID).characteristics
        to_subscribe: list[Characteristic] = []
        for _, iid in subscriptions:
            hap_char = accessory_chars.iid(iid)
            if (
                not hap_char
                or not hap_char.broadcast_events
                or iid in self._broadcast_notifications
            ):
                continue
            to_subscribe.append(hap_char)

        if not to_subscribe:
            return

        async with self._ble_request_lock:
            for hap_char in to_subscribe:
                iid = hap_char.iid
                if iid in self._broadcast_notifications:
                    continue  # check again with the lock
                logger.debug(
                    "%s: Subscribing to broadcast notify for iid: %s", self.name, iid
                )
                try:
                    await self._async_request_under_lock(
                        OpCode.CHAR_CONFIG, hap_char, ENABLE_BROADCAST_PAYLOAD
                    )
                except PDUStatusError:
                    logger.debug(
                        "%s: Failed to subscribe to broadcast events for %s",
                        self.name,
                        hap_char,
                    )
                    continue
                self._broadcast_notifications.add(iid)

    async def _async_restore_subscriptions(self) -> None:
        """Restore subscriptions and setup notifications after after connecting."""
        if not self._restore_pending or not self.client or not self.client.is_connected:
            return

        if not self.subscriptions:
            logger.debug("%s: No subscriptions to restore", self.name)
            self._restore_pending = False
            return

        assert self._operation_lock.locked(), "_operation_lock should be locked"
        await self._async_set_broadcast_encryption_key()
        subscriptions = list(self.subscriptions)
        logger.debug(
            "%s: Connected, resuming subscriptions: %s; rssi=%s",
            self.name,
            subscriptions,
            self.rssi,
        )
        await self._async_subscribe_broadcast_events(subscriptions)
        self._restore_pending = False
        # After we have restored subscriptions, we need to read
        # the state number again to make sure we are in sync
        protocol_param = await self._get_all_protocol_params()
        if protocol_param:
            self._update_state_num(protocol_param.state_number)
        self._async_schedule_start_notify_subscriptions()

    @operation_lock
    async def _async_start_notify_subscriptions(self) -> None:
        """Start notifications for the given subscriptions.

        If we have an error or are disconnected we do not want
        to retry, as it usually means the accessory indented
        to disconnect us and we are now using disconnected
        events or encrypted broadcasts to get updates.
        """
        if not self.client or not self.client.is_connected:
            return
        subscriptions = list(self.subscriptions)
        for _, iid in subscriptions:
            if iid in self._notifications:
                continue
            # The iid will not be in in self._notifications until
            # the _async_start_notify call returns.
            async with self._subscription_lock:
                if iid in self._notifications or not self.client.is_connected:
                    continue
                try:
                    await self._async_start_notify(iid)
                except BLEAK_EXCEPTIONS as ex:
                    # Likely disconnected before we could start notifications
                    # we will get disconnected events instead.
                    logger.debug(
                        "%s: Could not start notify for %s: %s; rssi=%s",
                        self.name,
                        iid,
                        ex,
                        self.rssi,
                    )

    @operation_lock
    @retry_bluetooth_connection_error()
    @disconnect_on_missing_services
    async def _process_config_changed(self, config_num: int) -> None:
        """Process a config change.

        This method is called when the config num changes.
        """
        await self._populate_accessories_and_characteristics()
        if self._restore_pending:
            await self._async_restore_subscriptions()

    @operation_lock
    @retry_bluetooth_connection_error()
    @disconnect_on_missing_services
    @restore_connection_and_resume
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

        info = self.accessories.aid(BLE_AID).services.first(
            service_type=ServicesTypes.PAIRING
        )
        char = info[CharacteristicsTypes.PAIRING_PAIRINGS]

        resp = await self._async_request(OpCode.CHAR_WRITE, char, request_tlv)

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
    @disconnect_on_missing_services
    async def get_characteristics(
        self,
        characteristics: list[tuple[int, int]],
    ) -> dict[tuple[int, int], dict[str, Any]]:
        return await self._get_characteristics_without_retry(characteristics)

    def _sort_characteristics_by_fetch_order(
        self, characteristics: list[Characteristic]
    ) -> list[Characteristic]:
        """Sort characteristics by fetch order.

        Characteristics are sorted by what we expect to be the most
        useful order to fetch them in. This is based on the following
        assumptions:

        The on/off state of the accessory is the most important
        characteristic to fetch.

        Color/Brightness/Color Temperature/etc are the next most important
        characteristics to fetch.

        The remaining characteristics are less important and can be
        fetched in any order except for ones that are unlikely to change
        frequently like the name, version, and thread status so they
        are fetched last.
        """
        # If we ever fetch which service is the primary we should
        # also sort by that.
        return sorted(
            characteristics,
            key=lambda char: CHAR_FETCH_PRIORITY.get(
                char.type,
                10 if char.broadcast_events or char.disconnected_events else 0,
            ),
            reverse=True,
        )

    @operation_lock
    @restore_connection_and_resume
    async def _get_characteristics_without_retry(
        self,
        characteristics: list[tuple[int, int]],
        notify_listeners: bool = False,
    ) -> dict[tuple[int, int], dict[str, Any]]:
        accessory_chars = self.accessories.aid(BLE_AID).characteristics
        return await self._get_characteristics_while_connected(
            [accessory_chars.iid(iid) for _, iid in characteristics], notify_listeners
        )

    async def _get_characteristics_while_connected(
        self,
        unordered_characteristics: list[Characteristic],
        notify_listeners: bool = False,
    ) -> dict[tuple[int, int], dict[str, Any]]:
        assert self._operation_lock.locked(), "_operation_lock should be locked"
        characteristics = self._sort_characteristics_by_fetch_order(
            unordered_characteristics
        )

        debug_enabled = logger.isEnabledFor(logging.DEBUG)
        if debug_enabled:
            logger.debug(
                "%s: Reading characteristics with rssi: %s",
                self.name,
                self.rssi,
            )

        results = {}

        async with self._ble_request_lock:
            for char in characteristics:
                if char.type in IGNORE_READ_CHARACTERISTICS:
                    logger.debug(
                        "%s: Ignoring characteristic %s",
                        self.name,
                        char.iid,
                    )
                    continue

                if debug_enabled:
                    logger.debug(
                        "%s: Reading characteristic %s (%s) with iid %s",
                        self.name,
                        char.description,
                        char.type,
                        char.iid,
                    )

                try:
                    data = await self._async_request_under_lock(OpCode.CHAR_READ, char)
                except PDUStatusError as ex:
                    # For the apple defines ones we know about we can avoid triggering
                    # this state, but we do not know all the vendor custom chars so
                    # we need to skip in this case.
                    if ex.status == PDUStatus.INVALID_REQUEST:
                        logger.debug(
                            "%s: Reading characteristic %s (%s) with iid %s resulted in an invalid request (skipped)",
                            self.name,
                            char.description,
                            char.type,
                            char.iid,
                        )
                        continue
                    logger.exception(
                        "%s: Reading characteristic %s (%s) with iid %s resulted in an error: %s",
                        self.name,
                        char.description,
                        char.type,
                        char.iid,
                        ex,
                    )
                    continue

                decoded = dict(TLV.decode_bytes(data))[1]

                logger.debug(
                    "%s: Read characteristic %s (%s) with iid %s got data, expected format is %s: data=%s decoded=%s",
                    self.name,
                    char.description,
                    char.type,
                    char.iid,
                    char.format,
                    data,
                    decoded,
                )

                try:
                    value = from_bytes(char, decoded)
                except struct.error as ex:
                    logger.debug(
                        "%s: Failed to decode characteristic %s (%s) with iid %s from %s: %s",
                        self.name,
                        char.description,
                        char.type,
                        char.iid,
                        decoded,
                        ex,
                    )
                    continue

                result_key = (BLE_AID, char.iid)
                result_value = {"value": value}
                results[result_key] = result_value

                if notify_listeners:
                    # Since it can take a while to read all the characteristics
                    # we want to notify the listeners as soon as we have the
                    # value for each characteristic.
                    single_results = {result_key: result_value}
                    self._callback_listeners(single_results)

        return results

    @operation_lock
    @retry_bluetooth_connection_error()
    @disconnect_on_missing_services
    @restore_connection_and_resume
    async def put_characteristics(
        self, characteristics: Iterable[tuple[int, int, Any]]
    ) -> dict[tuple[int, int], dict[str, Any]]:
        results: dict[tuple[int, int], Any] = {}
        logger.debug(
            "%s: Writing characteristics: %s; rssi=%s",
            self.name,
            characteristics,
            self.rssi,
        )
        accessory_chars = self.accessories.aid(BLE_AID).characteristics
        async with self._ble_request_lock:
            for aid, iid, value in characteristics:
                char = accessory_chars.iid(iid)
                result_key = (aid, iid)
                logger.debug(
                    "%s: Writing characteristics: iid=%s value=%s",
                    self.name,
                    iid,
                    value,
                )
                result = {}
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
                    await self._async_request_under_lock(
                        OpCode.CHAR_TIMED_WRITE, char, payload
                    )
                    await self._async_request_under_lock(OpCode.CHAR_EXEC_WRITE, char)
                elif CharacteristicPermissions.paired_write in char.perms:
                    payload = TLV.encode_list(
                        [(HAP_TLV.kTLVHAPParamValue, to_bytes(char, value))]
                    )
                    await self._async_request_under_lock(
                        OpCode.CHAR_WRITE, char, payload
                    )
                else:
                    result = {
                        "status": HapStatusCode.CANT_WRITE_READ_ONLY,
                        "description": HapStatusCode.CANT_WRITE_READ_ONLY.description,
                    }
                # results only set on failure, no status is success
                if not result:
                    if CharacteristicPermissions.paired_read in char.perms:
                        self._callback_listeners({result_key: {"value": value}})
                else:
                    results[result_key] = result

        return results

    @operation_lock
    @retry_bluetooth_connection_error()
    @force_fresh_connection
    @restore_connection_and_resume
    async def thread_provision(
        self,
        dataset: str,
    ) -> None:
        """
        Provision a device with Thread network credentials.

        The credentials should be provided in the meshcop/thread operational dataset format.
        """
        thread_service = self.accessories.aid(BLE_AID).services.first(
            service_type=ServicesTypes.THREAD_TRANSPORT
        )
        thread_control = thread_service[CharacteristicsTypes.THREAD_CONTROL_POINT]

        inner_request_tlv = TLV.encode_list(
            [
                (1, b"\x03"),
            ]
        )
        request_tlv = TLV.encode_list(
            [
                (TLV.kTLVHAPParamParamReturnResponse, bytearray(b"\x01")),
                (TLV.kTLVHAPParamValue, inner_request_tlv),
            ]
        )
        resp = await self._async_request(OpCode.CHAR_WRITE, thread_control, request_tlv)
        logger.debug("resp=%r", resp)

        decoded = Meshcop.decode(bytes.fromhex(dataset))
        thread_tlv = TLV.encode_list(
            [
                (1, decoded.networkname.encode("utf-8")),
                (2, decoded.channel.to_bytes(1, byteorder="little")),
                (3, decoded.panid.to_bytes(2, byteorder="little")),
                (4, decoded.extpanid),
                (5, decoded.networkkey),
            ]
        )
        unknown = 1
        inner_request_tlv = TLV.encode_list(
            [
                # TLV 1 is some sort of write/provision OpCode
                (1, b"\x01"),
                # TLV 2 contains the Thread network details
                (2, thread_tlv),
                # TLV 3 seems to be a bitfield or identifier; iOS sends 0 & Android sends 1
                # 1 has worked in testing
                (3, unknown.to_bytes(1, byteorder="little")),
            ]
        )
        request_tlv = TLV.encode_list(
            [
                (TLV.kTLVHAPParamParamReturnResponse, bytearray(b"\x01")),
                (TLV.kTLVHAPParamValue, inner_request_tlv),
            ]
        )

        try:
            resp = await self._async_request(
                OpCode.CHAR_WRITE, thread_control, request_tlv
            )
            # we shouldn't get a response
            logger.debug("Thread provision returned a success response: %r", resp)
        except Exception as e:
            # this is the expected code flow
            logger.debug(
                "Thread provision returned error (%r), this might not indicate a failure so ignoring.",
                e,
            )

        await self.shutdown()

    async def subscribe(self, characteristics: Iterable[tuple[int, int]]) -> None:
        """Subscribe to characteristics."""
        new_chars = await super().subscribe(characteristics)
        if not new_chars or not self.client or not self.client.is_connected:
            # Don't force a new connection if we are not already
            # connected as we will get disconnected events.
            return
        # We do not want to block setup of the accessory so we
        # do not wait for the result as any failures will be
        # handled by the retry logic or fallback to disconnected
        # events.
        async_create_task(self._async_subscribe(new_chars))
        self._async_schedule_start_notify_subscriptions()

    @operation_lock
    @retry_bluetooth_connection_error()
    @disconnect_on_missing_services
    @restore_connection_and_resume
    async def _async_subscribe(self, new_chars: Iterable[tuple[int, int]]) -> None:
        """Subscribe to new characteristics."""
        logger.debug("%s: subscribing to %s", self.name, new_chars)
        await self._populate_accessories_and_characteristics()
        if not self._broadcast_decryption_key:
            await self._async_set_broadcast_encryption_key()
        await self._async_subscribe_broadcast_events(new_chars)

    def _async_schedule_start_notify_subscriptions(self) -> None:
        """Schedule start notify subscriptions."""
        if self._start_notify_timer:
            self._start_notify_timer.cancel()
            self._start_notify_timer = None

        def _async_start_notify_subscriptions() -> None:
            """Start notify subscriptions."""
            self._start_notify_timer = None
            async_create_task(self._async_start_notify_subscriptions())

        loop = asyncio.get_running_loop()
        self._start_notify_timer = loop.call_later(
            START_NOTIFY_DEBOUNCE, _async_start_notify_subscriptions
        )

    async def unsubscribe(self, characteristics: Iterable[tuple[int, int]]) -> None:
        pass

    async def identify(self):
        info = self.accessories.aid(BLE_AID).services.first(
            service_type=ServicesTypes.ACCESSORY_INFORMATION
        )
        char = info[CharacteristicsTypes.IDENTIFY]

        await self.put_characteristics(
            [
                (BLE_AID, char.iid, True),
            ]
        )

    @operation_lock
    @retry_bluetooth_connection_error()
    @disconnect_on_missing_services
    @restore_connection_and_resume
    async def add_pairing(
        self, additional_controller_pairing_identifier, ios_device_ltpk, permissions
    ):
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

        info = self.accessories.aid(BLE_AID).services.first(
            service_type=ServicesTypes.PAIRING
        )
        char = info[CharacteristicsTypes.PAIRING_PAIRINGS]

        resp = await self._async_request(OpCode.CHAR_WRITE, char, request_tlv)

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
    @disconnect_on_missing_services
    @restore_connection_and_resume
    async def remove_pairing(self, pairingId: str) -> bool:
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

        info = self.accessories.aid(BLE_AID).services.first(
            service_type=ServicesTypes.PAIRING
        )
        char = info[CharacteristicsTypes.PAIRING_PAIRINGS]

        resp = await self._async_request(OpCode.CHAR_WRITE, char, request_tlv)

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

        await self._shutdown_if_primary_pairing_removed(pairingId)
        return True

    async def image(self, accessory: int, width: int, height: int) -> None:
        """Bluetooth devices don't return images."""
        return None
