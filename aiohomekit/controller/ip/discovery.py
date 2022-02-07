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

import uuid

from aiohomekit.controller.discovery import AbstractDiscovery, FinishPairing
from aiohomekit.exceptions import AlreadyPairedError
from aiohomekit.model.categories import Categories
from aiohomekit.model.feature_flags import FeatureFlags
from aiohomekit.model.status_flags import StatusFlags
from aiohomekit.protocol import perform_pair_setup_part1, perform_pair_setup_part2
from aiohomekit.protocol.statuscodes import to_status_code
from aiohomekit.utils import check_pin_format, pair_with_auth

from .connection import HomeKitConnection
from .pairing import IpPairing


class IpDiscovery(AbstractDiscovery):

    """
    A discovered IP HAP device that is unpaired.
    """

    def __init__(self, controller, discovery_data):
        self.controller = controller
        self.host = discovery_data["address"]
        self.port = discovery_data["port"]
        self.device_id = discovery_data["id"]
        self.info = discovery_data

        self.name = self.info["id"]
        self.id = self.info["id"]
        self.model = self.info.get("md", "")
        self.config_num = self.info.get("c#", 0)
        self.state_num = self.info.get("s#", 0)
        self.feature_flags = FeatureFlags(self.info.get("ff", 0))
        self.status_flags = StatusFlags(int(self.info.get("sf", 0)))
        self.category = Categories(1)

        self.connection = HomeKitConnection(None, self.host, self.port)

    def __repr__(self):
        return "IPDiscovery(host={self.host}, port={self.port})".format(self=self)

    def _update_from_discovery(self, data):
        pass

    async def _ensure_connected(self):
        await self.connection.ensure_connection()

    async def close(self):
        """
        Close the pairing's communications. This closes the session.
        """
        await self.connection.close()

    async def start_pairing(self, alias: str) -> FinishPairing:
        await self._ensure_connected()

        state_machine = perform_pair_setup_part1(pair_with_auth(self.feature_flags))
        request, expected = state_machine.send(None)
        while True:
            try:
                response = await self.connection.post_tlv(
                    "/pair-setup",
                    body=request,
                    expected=expected,
                )
                request, expected = state_machine.send(response)
            except StopIteration as result:
                # If the state machine raises a StopIteration then we have XXX
                salt, pub_key = result.value
                break

        async def finish_pairing(pin: str) -> IpPairing:
            check_pin_format(pin)

            state_machine = perform_pair_setup_part2(
                pin, str(uuid.uuid4()), salt, pub_key
            )
            request, expected = state_machine.send(None)

            while True:
                try:
                    response = await self.connection.post_tlv(
                        "/pair-setup",
                        body=request,
                        expected=expected,
                    )
                    request, expected = state_machine.send(response)
                except StopIteration as result:
                    # If the state machine raises a StopIteration then we have XXX
                    pairing = result.value
                    break

            pairing["AccessoryIP"] = self.host
            pairing["AccessoryPort"] = self.port
            pairing["Connection"] = "IP"

            obj = self.controller.pairings[alias] = IpPairing(self.controller, pairing)

            await self.connection.close()

            return obj

        return finish_pairing

    async def identify(self):
        await self._ensure_connected()

        response = await self.connection.post_json("/identify", {})

        if not response:
            return True

        code = to_status_code(response["code"])

        raise AlreadyPairedError(
            "Identify failed because: {reason} ({code}).".format(
                reason=code.description,
                code=code.value,
            )
        )

        return True
