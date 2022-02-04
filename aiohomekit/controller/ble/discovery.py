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
from typing import TYPE_CHECKING, Callable
import uuid

from bleak import BleakClient

from aiohomekit.model import CharacteristicsTypes, ServicesTypes
from aiohomekit.model.feature_flags import FeatureFlags
from aiohomekit.protocol import perform_pair_setup_part1, perform_pair_setup_part2

from .client import (
    char_read,
    char_write,
    drive_pairing_state_machine,
    get_characteristic,
    get_characteristic_iid,
)
from .pairing import BlePairing

if TYPE_CHECKING:
    from aiohomekit.controller import Controller


logger = logging.getLogger(__name__)


def parse_manufacturer_specific(input_data: bytes):
    """
    Parse the manufacturer specific data as returned via Bluez ManufacturerData. This skips the data for LEN, ADT and
    CoID as specified in Chapter 6.4.2.2 of the spec on page 124. Data therefore starts at TY (must be 0x06).
    :param input_data: manufacturer specific data as bytes
    :return: a dict containing the type (key 'type', value 'HomeKit'), the status flag (key 'sf'), human readable
             version of the status flag (key 'flags'), the device id (key 'device_id'), the accessory category
             identifier (key 'acid'), human readable version of the category (key 'category'), the global state number
             (key 'gsn'), the configuration number (key 'cn') and the compatible version (key 'cv')
    """
    logging.debug("manufacturer specific data: %s", input_data.hex())

    # the type must be 0x06 as defined on page 124 table 6-29
    ty = input_data[0]
    input_data = input_data[1:]
    if ty == 0x06:
        ty = "HomeKit"

        ail = input_data[0]
        logging.debug("advertising interval %s", f"{ail:02x}")
        length = ail & 0b00011111
        if length != 13:
            logging.debug("error with length of manufacturer data")
        input_data = input_data[1:]

        sf = input_data[0]
        flags = sf
        input_data = input_data[1:]

        device_id = (
            ":".join(input_data[:6].hex()[0 + i : 2 + i] for i in range(0, 12, 2))
        ).upper()
        input_data = input_data[6:]

        acid = int.from_bytes(input_data[:2], byteorder="little")
        input_data = input_data[2:]

        gsn = int.from_bytes(input_data[:2], byteorder="little")
        input_data = input_data[2:]

        cn = input_data[0]
        input_data = input_data[1:]

        cv = input_data[0]
        input_data = input_data[1:]
        if len(input_data) > 0:
            logging.debug("remaining data: %s", input_data.hex())
        return {
            "manufacturer": "apple",
            "type": ty,
            "sf": sf,
            "flags": flags,
            "id": device_id,
            "acid": acid,
            "s#": gsn,
            "c#": cn,
            "cv": cv,
            "ci": int(acid),
            "category": int(acid),
            "ff": 0,
            "md": "",
            "pv": 0,
            "statusflags": 0,
        }


class BleDiscovery:

    """
    A discovered BLE HAP device that is unpaired.
    """

    def __init__(self, controller: Controller, device) -> None:
        self.controller = controller
        self.device = device
        self.address = device.address
        self.info = parse_manufacturer_specific(
            device.metadata["manufacturer_data"][76]
        )
        self.info["name"] = device.name
        self.info["mac"] = device.address
        self.client = BleakClient(self.device)

    async def _ensure_connected(self):
        await self.client.__aenter__()

    async def perform_pairing(self, alias: str, pin: str) -> BlePairing:
        self.controller.check_pin_format(pin)
        finish_pairing = await self.start_pairing(alias)
        return await finish_pairing(pin)

    async def start_pairing(self, alias: str) -> Callable[[str], BlePairing]:
        await self._ensure_connected()

        ff_char = get_characteristic(
            self.client, ServicesTypes.PAIRING, CharacteristicsTypes.PAIRING_FEATURES
        )
        ff_iid = await get_characteristic_iid(self.client, ff_char)
        ff_raw = await char_read(self.client, None, None, ff_char.handle, ff_iid)
        ff = ff_raw[0]

        with_auth = False
        if ff & FeatureFlags.SUPPORTS_APPLE_AUTHENTICATION_COPROCESSOR:
            with_auth = True
        elif ff & FeatureFlags.SUPPORTS_SOFTWARE_AUTHENTICATION:
            with_auth = False

        salt, pub_key = await drive_pairing_state_machine(
            self.client,
            CharacteristicsTypes.PAIR_SETUP,
            perform_pair_setup_part1(
                with_auth=with_auth,
            ),
        )

        async def finish_pairing(pin: str) -> BlePairing:
            self.controller.check_pin_format(pin)

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
        await self._ensure_connected()

        char = get_characteristic(
            self.client,
            ServicesTypes.ACCESSORY_INFORMATION,
            CharacteristicsTypes.IDENTIFY,
        )
        iid = await get_characteristic_iid(self.client, char)

        await char_write(self.client, None, None, char.handle, iid, b"\x01")
