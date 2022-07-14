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
from typing import TYPE_CHECKING
import uuid

from bleak import BleakClient
from bleak.exc import BleakError

from aiohomekit.controller.abstract import AbstractDiscovery, FinishPairing
from aiohomekit.model import CharacteristicsTypes, ServicesTypes
from aiohomekit.model.feature_flags import FeatureFlags
from aiohomekit.protocol import perform_pair_setup_part1, perform_pair_setup_part2
from aiohomekit.utils import check_pin_format, pair_with_auth

from .client import (
    char_read,
    char_write,
    drive_pairing_state_machine,
    get_characteristic,
    get_characteristic_iid,
)
from .manufacturer_data import HomeKitAdvertisement
from .pairing import BlePairing

if TYPE_CHECKING:
    from aiohomekit.controller.ble.controller import BleController


logger = logging.getLogger(__name__)


class BleDiscovery(AbstractDiscovery):

    """
    A discovered BLE HAP device that is unpaired.
    """

    description: HomeKitAdvertisement

    def __init__(
        self,
        controller: BleController,
        device,
        description: HomeKitAdvertisement,
    ) -> None:
        self.description = description
        self.controller = controller
        self.device = device

        self.client = BleakClient(self.device)

    async def _ensure_connected(self):
        while not self.client.is_connected:
            try:
                await self.client.connect()
                break
            except BleakError as e:
                logger.debug("Failed to connect to %s: %s", self.client.address, str(e))

            if self.description.address != self.client.address:
                self.client = BleakClient(self.description.address)

            await asyncio.sleep(5)

    async def async_start_pairing(self, alias: str) -> FinishPairing:
        await self._ensure_connected()

        ff_char = get_characteristic(
            self.client,
            ServicesTypes.PAIRING,
            CharacteristicsTypes.PAIRING_FEATURES,
        )
        ff_iid = await get_characteristic_iid(self.client, ff_char)
        ff_raw = await char_read(self.client, None, None, ff_char.handle, ff_iid)
        ff = FeatureFlags(ff_raw[0])

        salt, pub_key = await drive_pairing_state_machine(
            self.client,
            CharacteristicsTypes.PAIR_SETUP,
            perform_pair_setup_part1(
                with_auth=pair_with_auth(ff),
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

            pairing["AccessoryAddress"] = self.description.address
            pairing["Connection"] = "BLE"

            obj = self.controller.pairings[alias] = BlePairing(self.controller, pairing)

            return obj

        return finish_pairing

    async def async_identify(self) -> None:
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

    def _async_process_advertisement(self, description: HomeKitAdvertisement):
        self.description = description