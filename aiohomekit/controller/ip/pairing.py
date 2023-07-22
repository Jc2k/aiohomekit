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
from collections.abc import Iterable
from datetime import timedelta
from itertools import groupby
import logging
from operator import itemgetter
from typing import Any

from aiohomekit.controller.abstract import AbstractController, AbstractPairingData
from aiohomekit.exceptions import (
    AccessoryDisconnectedError,
    AuthenticationError,
    HttpErrorResponse,
    HttpException,
    InvalidError,
    UnknownError,
    UnpairedError,
)
import aiohomekit.hkjson as hkjson
from aiohomekit.http import HttpContentTypes
from aiohomekit.model import Accessories, AccessoriesState, Transport
from aiohomekit.model.characteristics import (
    CharacteristicPermissions,
    CharacteristicsTypes,
)
from aiohomekit.protocol import error_handler
from aiohomekit.protocol.statuscodes import HapStatusCode, to_status_code
from aiohomekit.protocol.tlv import TLV
from aiohomekit.utils import asyncio_timeout
from aiohomekit.uuid import normalize_uuid
from aiohomekit.zeroconf import HomeKitService, ZeroconfPairing

from .connection import SecureHomeKitConnection

logger = logging.getLogger(__name__)


EMPTY_EVENT = {}


def format_characteristic_list(data):
    tmp = {}
    for c in data["characteristics"]:
        key = (c["aid"], c["iid"])
        del c["aid"]
        del c["iid"]

        if "status" in c and c["status"] == 0:
            del c["status"]
        if "status" in c and c["status"] != 0:
            c["description"] = to_status_code(c["status"]).description
        tmp[key] = c
    return tmp


class IpPairing(ZeroconfPairing):
    """
    This represents a paired HomeKit IP accessory.
    """

    def __init__(
        self, controller: AbstractController, pairing_data: AbstractPairingData
    ) -> None:
        """
        Initialize a Pairing by using the data either loaded from file or obtained after calling
        Controller.perform_pairing().

        :param pairing_data:
        """
        self.pairing_data = pairing_data
        self.connection = SecureHomeKitConnection(self, self.pairing_data)
        self.supports_subscribe = True

        super().__init__(controller, pairing_data)

    @property
    def is_connected(self) -> bool:
        return self.connection.is_connected

    @property
    def is_available(self) -> bool:
        """Returns true if the device is currently available."""
        return self.connection.is_connected

    @property
    def transport(self) -> Transport:
        """The transport used for the connection."""
        return Transport.IP

    @property
    def poll_interval(self) -> timedelta:
        """Returns how often the device should be polled."""
        return timedelta(minutes=1)

    @property
    def name(self) -> str:
        """Return the name of the pairing with the address."""
        if self.description:
            return f"{self.description.name} [{self.connection.host}:{self.connection.port}] (id={self.id})"
        return f"[{self.connection.host}:{self.connection.port}] (id={self.id})"

    def event_received(self, event):
        self._callback_listeners(format_characteristic_list(event))

    async def connection_made(self, secure):
        if not secure:
            return

        # Let our listeners know the connection is available again
        self._callback_listeners(EMPTY_EVENT)

        if self.subscriptions:
            await self.subscribe(self.subscriptions)

    async def _ensure_connected(self):
        if self._shutdown:
            return
        connection = self.connection
        try:
            async with asyncio_timeout(10):
                await connection.ensure_connection()
        except asyncio.TimeoutError:
            last_connector_error = connection.last_connector_error
            if not last_connector_error or isinstance(
                last_connector_error, asyncio.TimeoutError
            ):
                raise AccessoryDisconnectedError(
                    f"Timeout while waiting for connection to device {self.connection.host}:{self.connection.port}"
                )
            # The exception name is included since otherwise the error message
            # is not very helpful as it could be something like `step 3`
            raise AccessoryDisconnectedError(
                f"Error while connecting to device {self.connection.host}:{self.connection.port}: "
                f"{last_connector_error} ({type(last_connector_error).__name__})"
            )

        if not self.connection.is_connected:
            raise AccessoryDisconnectedError(
                f"Ensure connection returned but still not connected: {self.connection.host}:{self.connection.port}"
            )

        else:
            self._callback_availability_changed(True)

    async def close(self) -> None:
        """
        Close the pairing's communications. This closes the session.
        """
        await self.connection.close()
        await asyncio.sleep(0)

    async def list_accessories_and_characteristics(self) -> list[dict[str, Any]]:
        """
        This retrieves a current set of accessories and characteristics behind this pairing.

        :return: the accessory data as described in the spec on page 73 and following
        :raises AccessoryNotFoundError: if the device can not be found via zeroconf
        """
        await self._ensure_connected()

        response = await self.connection.get_json("/accessories")

        accessories = response["accessories"]

        for accessory in accessories:
            for service in accessory["services"]:
                service["type"] = normalize_uuid(service["type"])

                for characteristic in service["characteristics"]:
                    characteristic["type"] = normalize_uuid(characteristic["type"])

        self._accessories_state = AccessoriesState(
            Accessories.from_list(accessories), self.config_num or 0
        )
        self._update_accessories_state_cache()
        return accessories

    async def list_pairings(self):
        """
        This method returns all pairings of a HomeKit accessory. This always includes the local controller and can only
        be done by an admin controller.

        The keys in the resulting dicts are:
         * pairingId: the pairing id of the controller
         * publicKey: the ED25519 long-term public key of the controller
         * permissions: bit value for the permissions
         * controllerType: either admin or regular

        :return: a list of dicts
        :raises: UnknownError: if it receives unexpected data
        :raises: UnpairedError: if the polled accessory is not paired
        """
        await self._ensure_connected()

        data = await self.connection.post_tlv(
            "/pairings",
            [(TLV.kTLVType_State, TLV.M1), (TLV.kTLVType_Method, TLV.ListPairings)],
        )

        if not (data[0][0] == TLV.kTLVType_State and data[0][1] == TLV.M2):
            raise UnknownError("unexpected data received: " + str(data))

        if (
            data[1][0] == TLV.kTLVType_Error
            and data[1][1] == TLV.kTLVError_Authentication
        ):
            raise UnpairedError("Must be paired")

        tmp = []
        r = {}
        for d in data[1:]:
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
        characteristics,
    ):
        """
        This method is used to get the current readouts of any characteristic of the accessory.

        :param characteristics: a list of 2-tupels of accessory id and instance id
        :param include_meta: if True, include meta information about the characteristics. This contains the format and
                             the various constraints like maxLen and so on.
        :param include_perms: if True, include the permissions for the requested characteristics.
        :param include_type: if True, include the type of the characteristics in the result. See CharacteristicsTypes
                             for translations.
        :param include_events: if True on a characteristics that supports events, the result will contain information if
                               the controller currently is receiving events for that characteristic. Key is 'ev'.
        :return: a dict mapping 2-tupels of aid and iid to dicts with value or status and description, e.g.
                 {(1, 8): {'value': 23.42}
                  (1, 37): {'description': 'Resource does not exist.', 'status': -70409}
                 }
        """
        await self._ensure_connected()

        if not self.accessories:
            await self.list_accessories_and_characteristics()

        url = "/characteristics?id=" + ",".join(
            str(x[0]) + "." + str(x[1]) for x in set(characteristics)
        )

        response = await self.connection.get_json(url)

        return format_characteristic_list(response)

    async def put_characteristics(
        self, characteristics: Iterable[tuple[int, int, Any]]
    ) -> dict[tuple[int, int], dict[str, Any]]:
        """
        Update the values of writable characteristics. The characteristics have to be identified by accessory id (aid),
        instance id (iid). If do_conversion is False (the default), the value must be of proper format for the
        characteristic since no conversion is done. If do_conversion is True, the value is converted.

        :param characteristics: a list of 3-tupels of accessory id, instance id and the value
        :param do_conversion: select if conversion is done (False is default)
        :return: a dict from (aid, iid) onto {status, description}
        :raises FormatError: if the input value could not be converted to the target type and conversion was
                             requested
        """
        await self._ensure_connected()

        if not self.accessories:
            await self.list_accessories_and_characteristics()

        char_payload: list[dict[str, Any]] = []
        listener_update: dict[tuple[int, int], dict[str, Any]] = {}
        for characteristic in characteristics:
            aid, iid, value = characteristic
            char_payload.append({"aid": aid, "iid": iid, "value": value})
            accessory_chars = self.accessories.aid(aid).characteristics
            char = accessory_chars.iid(iid)
            if CharacteristicPermissions.paired_read in char.perms:
                listener_update[(aid, iid)] = {"value": value}

        response = await self.connection.put_json(
            "/characteristics", {"characteristics": char_payload}
        )
        response_status: dict[tuple[int, int], dict[str, Any]] = {}
        if response:
            # If there is a response it means something failed so
            # we need to remove the listener update for the failed
            # characteristics.
            for characteristic in response["characteristics"]:
                aid, iid = characteristic["aid"], characteristic["iid"]
                key = (aid, iid)
                status = characteristic["status"]
                status_code = to_status_code(status).description
                if status_code != HapStatusCode.SUCCESS:
                    listener_update.pop(key, None)
                response_status[key] = {"status": status, "description": status_code}

        if listener_update:
            self._callback_listeners(listener_update)

        return response_status

    async def thread_provision(
        self,
        dataset: str,
    ) -> None:
        """Provision a device with Thread network credentials."""

    async def subscribe(self, characteristics):
        await super().subscribe(set(characteristics))

        if not self.supports_subscribe:
            logger.info(
                "This device does not support push, so only polling operations will be supported during this session"
            )
            return

        try:
            await self._ensure_connected()
        except AccessoryDisconnectedError:
            logger.debug(
                "Attempted to subscribe to characteristics but could not connect to accessory"
            )
            return {}

        try:
            return await self._update_subscriptions(characteristics, True)
        except AccessoryDisconnectedError:
            self.supports_subscribe = False
            return {}

    async def unsubscribe(self, characteristics):
        if not self.connection.is_connected:
            # If not connected no need to unsubscribe
            await super().unsubscribe(characteristics)
            return {}

        await self._ensure_connected()
        char_set = set(characteristics)
        status = await self._update_subscriptions(characteristics, False)
        for id_tuple in status:
            char_set.discard(id_tuple)

        await super().unsubscribe(char_set)
        return status

    async def _update_subscriptions(self, characteristics, ev):
        """Subscribe or unsubscribe to characteristics."""
        status = {}
        # We do one aid at a time to match what iOS does
        # even though its inefficient
        # https://github.com/home-assistant/core/issues/37996
        #
        # Prebuild the payloads to avoid the set size changing
        # between await calls
        char_payloads = [
            [{"aid": aid, "iid": iid, "ev": ev} for aid, iid in aid_iids]
            for _, aid_iids in groupby(characteristics, key=itemgetter(0))
        ]
        for char_payload in char_payloads:
            response = await self.connection.put_json(
                "/characteristics",
                {"characteristics": char_payload},
            )
            if response:
                # An empty body is a success response
                for row in response.get("characteristics", []):
                    status[(row["aid"], row["iid"])] = {
                        "status": row["status"],
                        "description": to_status_code(row["status"]).description,
                    }

        return status

    async def async_populate_accessories_state(
        self, force_update: bool = False, attempts: int | None = None
    ) -> bool:
        """Populate the state of all accessories.

        This method should try not to fetch all the accessories unless
        we know the config num is out of date or force_update is True
        """
        if not self.accessories or force_update:
            await self.list_accessories_and_characteristics()

    async def _process_config_changed(self, config_num: int) -> None:
        """Process a config change.

        This method is called when the config num changes.
        """
        await self.list_accessories_and_characteristics()
        self._accessories_state = AccessoriesState(
            self._accessories_state.accessories, config_num
        )
        self._callback_and_save_config_changed(self.config_num)

    async def _process_disconnected_events(self):
        """Process any events that happened while we were disconnected.

        We don't disconnect in IP so there is no need to do anything here.
        """

    async def identify(self):
        """
        This call can be used to trigger the identification of a paired accessory. A successful call should
        cause the accessory to perform some specific action by which it can be distinguished from the others (blink a
        LED for example).

        It uses the identify characteristic as described on page 152 of the spec.

        :return True, if the identification was run, False otherwise
        """
        await self._ensure_connected()

        if not self.accessories:
            await self.list_accessories_and_characteristics()

        # we are looking for a characteristic of the identify type
        identify_type = CharacteristicsTypes.IDENTIFY

        # search all accessories, all services and all characteristics
        logger.debug("Searching for identify characteristic in %s", self.accessories)
        for accessory in self.accessories:
            aid = accessory.aid
            for service in accessory.services:
                for characteristic in service.characteristics:
                    iid = characteristic.iid
                    c_type = normalize_uuid(characteristic.type)
                    if identify_type == c_type:
                        # found the identify characteristic, so let's put a value there
                        if not await self.put_characteristics([(aid, iid, True)]):
                            return True
        return False

    async def add_pairing(
        self, additional_controller_pairing_identifier, ios_device_ltpk, permissions
    ):
        await self._ensure_connected()

        if permissions == "User":
            permissions = TLV.kTLVType_Permission_RegularUser
        elif permissions == "Admin":
            permissions = TLV.kTLVType_Permission_AdminUser
        else:
            raise RuntimeError(f"Unknown permission: {permissions}")

        request_tlv = [
            (TLV.kTLVType_State, TLV.M1),
            (TLV.kTLVType_Method, TLV.AddPairing),
            (
                TLV.kTLVType_Identifier,
                additional_controller_pairing_identifier.encode(),
            ),
            (TLV.kTLVType_PublicKey, bytes.fromhex(ios_device_ltpk)),
            (TLV.kTLVType_Permissions, permissions),
        ]

        data = dict(await self.connection.post_tlv("/pairings", request_tlv))

        if data.get(TLV.kTLVType_State, TLV.M2) != TLV.M2:
            raise InvalidError("Unexpected state after add pairing request")

        if TLV.kTLVType_Error in data:
            error_handler(data[TLV.kTLVType_Error], "M2")

        return True

    async def remove_pairing(self, pairingId: str) -> bool:
        """
        Remove a pairing between the controller and the accessory. The pairing data is delete on both ends, on the
        accessory and the controller.

        Important: no automatic saving of the pairing data is performed. If you don't do this, the accessory seems still
            to be paired on the next start of the application.

        :param alias: the controller's alias for the accessory
        :param pairingId: the pairing id to be removed
        :raises AuthenticationError: if the controller isn't authenticated to the accessory.
        :raises AccessoryNotFoundError: if the device can not be found via zeroconf
        :raises UnknownError: on unknown errors
        """
        await self._ensure_connected()

        request_tlv = [
            (TLV.kTLVType_State, TLV.M1),
            (TLV.kTLVType_Method, TLV.RemovePairing),
            (TLV.kTLVType_Identifier, pairingId.encode("utf-8")),
        ]

        data = dict(await self.connection.post_tlv("/pairings", request_tlv))

        if data.get(TLV.kTLVType_State, TLV.M2) != TLV.M2:
            raise InvalidError("Unexpected state after removing pairing request")

        if TLV.kTLVType_Error in data:
            if data[TLV.kTLVType_Error] == TLV.kTLVError_Authentication:
                raise AuthenticationError("Remove pairing failed: insufficient access")
            raise UnknownError("Remove pairing failed: unknown error")

        await self._shutdown_if_primary_pairing_removed(pairingId)
        return True

    async def image(self, accessory: int, width: int, height: int) -> bytes:
        await self._ensure_connected()

        try:
            resp = await self.connection.post(
                "/resource",
                content_type=HttpContentTypes.JSON,
                body=hkjson.dump_bytes(
                    {
                        "aid": accessory,
                        "resource-type": "image",
                        "image-width": width,
                        "image-height": height,
                    }
                ),
            )

        except HttpException:
            return None

        except HttpErrorResponse:
            return None

        except AccessoryDisconnectedError:
            return None

        return resp.body

    def _async_description_update(self, description: HomeKitService | None) -> None:
        """We have new zeroconf metadata for this device."""
        super()._async_description_update(description)

        # If we are not connected, or are in the process of reconnecting, hasten the process
        self.connection.reconnect_soon()
