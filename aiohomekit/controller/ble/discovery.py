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

import logging
from typing import TYPE_CHECKING
import uuid

from bleak import BleakClient

from aiohomekit.controller.discovery import AbstractDiscovery, FinishPairing
from aiohomekit.model import CharacteristicsTypes, ServicesTypes
from aiohomekit.model.feature_flags import FeatureFlags
from aiohomekit.protocol import perform_pair_setup_part1, perform_pair_setup_part2
from aiohomekit.utils import check_pin_format

from .client import (
    char_write,
    drive_pairing_state_machine,
    get_characteristic,
    get_characteristic_iid,
)
from .manufacturer_data import ManufacturerData
from .pairing import BlePairing

if TYPE_CHECKING:
    from aiohomekit.controller.ble.controller import BleController


logger = logging.getLogger(__name__)


class BleDiscovery(AbstractDiscovery):

    """
    A discovered BLE HAP device that is unpaired.
    """

    def __init__(
        self,
        controller: BleController,
        device,
        info: ManufacturerData,
        feature_flags: FeatureFlags,
    ) -> None:
        self.controller = controller
        self.device = device

        self.name = device.name
        self.id = info.device_id
        self.feature_flags = feature_flags
        self.status_flags = info.status_flags
        self.config_num = info.config_num
        self.state_num = info.status_num
        self.model = ""
        self.category = info.category

        self.address = device.address
        self.info = info
        self.client = BleakClient(self.device)

    async def _ensure_connected(self):
        await self.client.__aenter__()

    async def start_pairing(self, alias: str) -> FinishPairing:
        salt, pub_key = await drive_pairing_state_machine(
            self.client,
            CharacteristicsTypes.PAIR_SETUP,
            perform_pair_setup_part1(
                with_auth=self.pair_with_auth,
            ),
        )

        async def finish_pairing(pin: str) -> BlePairing:
            check_pin_format(pin)

            pairing = await drive_pairing_state_machine(
                self.client,
                CharacteristicsTypes.PAIR_SETUP,
                perform_pair_setup_part2(
                    pin,
                    str(uuid.uuid4()),
                    salt,
                    pub_key,
                ),
            )

            pairing["AccessoryAddress"] = self.address
            pairing["Connection"] = "BLE"

            obj = self.controller.pairings[alias] = BlePairing(self.controller, pairing)

            return obj

        return finish_pairing

    async def identify(self) -> None:
        if self.paired:
            raise RuntimeError("Cannot anonymously identify a paired accessory")

        async with self.client as client:
            char = get_characteristic(
                client,
                ServicesTypes.ACCESSORY_INFORMATION,
                CharacteristicsTypes.IDENTIFY,
            )
            iid = await get_characteristic_iid(client, char)

            await char_write(client, None, None, char.handle, iid, b"\x01")

    def _async_process_advertisement(self, advertisement):
        pass
