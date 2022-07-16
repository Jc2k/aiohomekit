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

from aiohomekit.controller.abstract import FinishPairing
from aiohomekit.exceptions import AlreadyPairedError
from aiohomekit.protocol import perform_pair_setup_part1, perform_pair_setup_part2
from aiohomekit.protocol.statuscodes import to_status_code
from aiohomekit.utils import check_pin_format, pair_with_auth
from aiohomekit.zeroconf import HomeKitService, ZeroconfDiscovery

from .connection import HomeKitConnection
from .pairing import IpPairing


class IpDiscovery(ZeroconfDiscovery):

    """
    A discovered IP HAP device that is unpaired.
    """

    def __init__(self, controller, description: HomeKitService):
        super().__init__(description)
        self.controller = controller
        self.connection = HomeKitConnection(None, description.address, description.port)

    def __repr__(self):
        return f"IPDiscovery(host={self.description.address}, port={self.description.port})"

    async def _ensure_connected(self):
        await self.connection.ensure_connection()

    async def close(self):
        """
        Close the pairing's communications. This closes the session.
        """
        await self.connection.close()

    async def async_start_pairing(self, alias: str) -> FinishPairing:
        await self._ensure_connected()

        state_machine = perform_pair_setup_part1(
            pair_with_auth(self.description.feature_flags)
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

            pairing["AccessoryIP"] = self.description.address
            pairing["AccessoryPort"] = self.description.port
            pairing["Connection"] = "IP"

            obj = self.controller.pairings[alias] = IpPairing(self.controller, pairing)

            await self.connection.close()

            return obj

        return finish_pairing

    async def async_identify(self) -> None:
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
