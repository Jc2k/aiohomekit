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

from aiohomekit.exceptions import AlreadyPairedError
from aiohomekit.model.feature_flags import FeatureFlags
from aiohomekit.protocol import perform_pair_setup_part1, perform_pair_setup_part2
from aiohomekit.protocol.statuscodes import HapStatusCodes

from .connection import HomeKitConnection
from .pairing import IpPairing


class IpDiscovery:

    """
    A discovered IP HAP device that is unpaired.
    """

    def __init__(self, controller, discovery_data):
        self.controller = controller
        self.host = discovery_data["address"]
        self.port = discovery_data["port"]
        self.device_id = discovery_data["id"]
        self.info = discovery_data

        self.connection = HomeKitConnection(None, self.host, self.port)

    def __repr__(self):
        return "IPDiscovery(host={self.host}, port={self.port})".format(self=self)

    async def _ensure_connected(self):
        await self.connection.ensure_connection()

    async def close(self):
        """
        Close the pairing's communications. This closes the session.
        """
        await self.connection.close()

    async def perform_pairing(self, alias, pin):
        self.controller.check_pin_format(pin)
        finish_pairing = await self.start_pairing(alias)
        return await finish_pairing(pin)

    async def start_pairing(self, alias):
        await self._ensure_connected()

        with_auth = False
        if self.info["ff"] & FeatureFlags.SUPPORTS_APPLE_AUTHENTICATION_COPROCESSOR:
            with_auth = True
        elif self.info["ff"] & FeatureFlags.SUPPORTS_SOFTWARE_AUTHENTICATION:
            with_auth = False

        state_machine = perform_pair_setup_part1(with_auth)
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

        async def finish_pairing(pin):
            self.controller.check_pin_format(pin)

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

        code = response["code"]

        raise AlreadyPairedError(
            "Identify failed because: {reason} ({code}).".format(
                reason=HapStatusCodes[code],
                code=code,
            )
        )

        return True
