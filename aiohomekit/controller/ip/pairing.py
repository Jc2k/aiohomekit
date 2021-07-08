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
from itertools import groupby
import json
import logging
from operator import itemgetter

from aiohomekit.controller.pairing import AbstractPairing
from aiohomekit.exceptions import (
    AccessoryDisconnectedError,
    AuthenticationError,
    HttpErrorResponse,
    HttpException,
    InvalidError,
    UnknownError,
    UnpairedError,
)
from aiohomekit.http import HttpContentTypes
from aiohomekit.model.characteristics import CharacteristicsTypes
from aiohomekit.model.services import ServicesTypes
from aiohomekit.protocol import error_handler
from aiohomekit.protocol.statuscodes import to_status_code
from aiohomekit.protocol.tlv import TLV

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


class IpPairing(AbstractPairing):
    """
    This represents a paired HomeKit IP accessory.
    """

    def __init__(self, controller, pairing_data):
        """
        Initialize a Pairing by using the data either loaded from file or obtained after calling
        Controller.perform_pairing().

        :param pairing_data:
        """
        super().__init__(controller)

        self.pairing_data = pairing_data
        self.connection = SecureHomeKitConnection(self, self.pairing_data)
        self.supports_subscribe = True

    def event_received(self, event):
        self._callback_listeners(format_characteristic_list(event))

    def _callback_listeners(self, event):
        for listener in self.listeners:
            try:
                listener(event)
            except Exception:
                logger.exception("Unhandled error when processing event")

    async def connection_made(self, secure):
        if not secure:
            return

        # Let our listeners know the connection is available again
        self._callback_listeners(EMPTY_EVENT)

        if self.subscriptions:
            await self.subscribe(self.subscriptions)

    async def _ensure_connected(self):
        try:
            await asyncio.wait_for(self.connection.ensure_connection(), 10)
        except asyncio.TimeoutError:
            raise AccessoryDisconnectedError(
                "Timeout while waiting for connection to device"
            )

        if not self.connection.is_connected:
            raise AccessoryDisconnectedError(
                "Ensure connection returned but still not connected"
            )

    async def close(self):
        """
        Close the pairing's communications. This closes the session.
        """
        await self.connection.close()
        await asyncio.sleep(0)

    async def list_accessories_and_characteristics(self):
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
                service["type"] = service["type"].upper()
                try:
                    service["type"] = ServicesTypes.get_uuid(service["type"])
                except KeyError:
                    pass

                for characteristic in service["characteristics"]:
                    characteristic["type"] = characteristic["type"].upper()
                    try:
                        characteristic["type"] = CharacteristicsTypes.get_uuid(
                            characteristic["type"]
                        )
                    except KeyError:
                        pass

        self.pairing_data["accessories"] = accessories
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
        include_meta=False,
        include_perms=False,
        include_type=False,
        include_events=False,
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

        if "accessories" not in self.pairing_data:
            await self.list_accessories_and_characteristics()

        url = "/characteristics?id=" + ",".join(
            str(x[0]) + "." + str(x[1]) for x in set(characteristics)
        )
        if include_meta:
            url += "&meta=1"
        if include_perms:
            url += "&perms=1"
        if include_type:
            url += "&type=1"
        if include_events:
            url += "&ev=1"

        response = await self.connection.get_json(url)

        return format_characteristic_list(response)

    async def put_characteristics(self, characteristics):
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

        if "accessories" not in self.pairing_data:
            await self.list_accessories_and_characteristics()

        data = []
        characteristics_set = set()
        for characteristic in characteristics:
            aid = characteristic[0]
            iid = characteristic[1]
            value = characteristic[2]
            characteristics_set.add(f"{aid}.{iid}")
            data.append({"aid": aid, "iid": iid, "value": value})
        data = {"characteristics": data}

        response = await self.connection.put_json("/characteristics", data)
        if response:
            data = {
                (d["aid"], d["iid"]): {
                    "status": d["status"],
                    "description": to_status_code(d["status"]).description,
                }
                for d in response["characteristics"]
            }
            return data

        return {}

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

        for _, aid_iids in groupby(characteristics, key=itemgetter(0)):
            response = await self.connection.put_json(
                "/characteristics",
                {
                    "characteristics": [
                        {"aid": aid, "iid": iid, "ev": ev} for aid, iid in aid_iids
                    ]
                },
            )
            if response:
                # An empty body is a success response
                for row in response.get("characteristics", []):
                    status[(row["aid"], row["iid"])] = {
                        "status": row["status"],
                        "description": to_status_code(row["status"]).description,
                    }

        return status

    async def identify(self):
        """
        This call can be used to trigger the identification of a paired accessory. A successful call should
        cause the accessory to perform some specific action by which it can be distinguished from the others (blink a
        LED for example).

        It uses the identify characteristic as described on page 152 of the spec.

        :return True, if the identification was run, False otherwise
        """
        await self._ensure_connected()

        if "accessories" not in self.pairing_data:
            await self.list_accessories_and_characteristics()

        # we are looking for a characteristic of the identify type
        identify_type = CharacteristicsTypes.get_uuid(CharacteristicsTypes.IDENTIFY)

        # search all accessories, all services and all characteristics
        for accessory in self.pairing_data["accessories"]:
            aid = accessory["aid"]
            for service in accessory["services"]:
                for characteristic in service["characteristics"]:
                    iid = characteristic["iid"]
                    c_type = CharacteristicsTypes.get_uuid(characteristic["type"])
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

    async def remove_pairing(self, pairingId):
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

        return True

    async def image(self, accessory, width, height):
        await self._ensure_connected()

        try:
            resp = await self.connection.post(
                "/resource",
                content_type=HttpContentTypes.JSON,
                body=json.dumps(
                    {
                        "aid": accessory,
                        "resource-type": "image",
                        "image-width": width,
                        "image-height": height,
                    }
                ).encode("utf-8"),
            )

        except HttpException:
            return None

        except HttpErrorResponse:
            return None

        except AccessoryDisconnectedError:
            return None

        return resp.body
