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

from aiohomekit.controller.abstract import FinishPairing
from aiohomekit.utils import check_pin_format, pair_with_auth
from aiohomekit.zeroconf import ZeroconfDiscovery

from .connection import CoAPHomeKitConnection
from .pairing import CoAPPairing


class CoAPDiscovery(ZeroconfDiscovery):

    """
    A discovered CoAP HAP device that is unpaired.
    """

    def __init__(self, controller, discovery_data):
        self.controller = controller
        self.host = discovery_data["address"]
        self.port = discovery_data["port"]
        self.device_id = discovery_data["id"]
        self.info = discovery_data

        self._update_from_discovery(discovery_data)

        self.connection = CoAPHomeKitConnection(None, self.host, self.port)

    def __repr__(self):
        return "CoAPDiscovery(host={self.host}, port={self.port})".format(self=self)

    async def _ensure_connected(self):
        """
        No preparation needs to be done for pair setup over CoAP.
        """
        return

    async def close(self):
        """
        No teardown needs to be done for pair setup over CoAP.
        """
        return

    async def async_identify(self) -> None:
        return await self.connection.do_identify()

    async def async_start_pairing(self, alias: str) -> FinishPairing:
        salt, srpB = await self.connection.do_pair_setup(
            pair_with_auth(self.feature_flags)
        )

        async def finish_pairing(pin: str) -> CoAPPairing:
            check_pin_format(pin)

            pairing = await self.connection.do_pair_setup_finish(pin, salt, srpB)
            pairing["AccessoryIP"] = self.host
            pairing["AccessoryPort"] = self.port
            pairing["Connection"] = "CoAP"

            obj = self.controller.pairings[alias] = CoAPPairing(
                self.controller, pairing
            )

            return obj

        return finish_pairing
