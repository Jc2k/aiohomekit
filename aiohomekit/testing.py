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

import base64
import logging
from typing import Dict

from aiohomekit import exceptions
from aiohomekit.controller import Controller
from aiohomekit.controller.ip.connection import HomeKitConnection
from aiohomekit.controller.pairing import AbstractPairing
from aiohomekit.exceptions import AccessoryNotFoundError
from aiohomekit.model import Accessories
from aiohomekit.model.characteristics import CharacteristicsTypes

_LOGGER = logging.getLogger(__name__)

FAKE_CAMERA_IMAGE = (
    b"/9j/2wBDAAMCAgICAgMCAgIDAwMDBAYEBAQEBAgGBgUGCQgKCgkICQkKDA8MCgsOCwkJDRE"
    b"NDg8QEBEQCgwSExIQEw8QEBD/yQALCAABAAEBAREA/8wABgAQEAX/2gAIAQEAAD8A0s8g/9k="
)


class FakeDiscovery:
    def __init__(
        self, controller: "FakeController", device_id: str, accessories: Accessories
    ):
        self.controller = controller
        self.device_id = device_id
        self.accessories = accessories

        self.pairing_code = "111-22-333"

    @property
    def info(self):
        sf = 0

        # Is accessory unpaired?
        if self.device_id not in self.controller.pairings:
            sf = sf | 0x01

        return {
            "name": "TestDevice",
            "address": "127.0.0.1",
            "port": 8080,
            "md": "TestDevice",
            "pv": "1.0",
            "id": self.device_id,
            "c#": 1,
            "s#": 1,
            "ff": 0,
            "ci": 0,
            "sf": sf,
        }

    async def perform_pairing(self, alias: str, pin):
        finish_pairing = await self.start_pairing(alias)
        return await finish_pairing(pin)

    async def start_pairing(self, alias: str):
        if self.device_id in self.controller.pairings:
            raise exceptions.AlreadyPairedError(f"{self.device_id} already paired")

        async def finish_pairing(pairing_code):
            if pairing_code != self.pairing_code:
                raise exceptions.AuthenticationError("M4")
            pairing_data = {}
            pairing_data["AccessoryIP"] = self.info["address"]
            pairing_data["AccessoryPort"] = self.info["port"]
            pairing_data["Connection"] = "IP"

            obj = self.controller.pairings[alias] = FakePairing(
                self.controller, pairing_data, self.accessories
            )
            return obj

        return finish_pairing

    async def identify(self):
        return True


class PairingTester:
    """
    A holding class for test-only helpers.

    This is done to minimize the difference between a FakePairing and a real pairing.
    """

    def __init__(self, pairing):
        self.pairing = pairing
        self.events_enabled = True

        self.characteristics = {}
        self.services = {}

        name_uuid = CharacteristicsTypes.get_uuid(CharacteristicsTypes.NAME)
        for accessory in self.pairing.accessories:
            for service in accessory.services:
                service_map = {}
                for char in service.characteristics:
                    self.characteristics[(accessory.aid, char.iid)] = char
                    service_map[char.type] = char
                    if char.type == name_uuid:
                        self.services[char.get_value()] = service_map

    def set_events_enabled(self, value):
        self.events_enabled = value

    def update_named_service(self, name: str, new_values):
        """
        Finds a named service then sets characteristics by type.

        pairing.test.update_named_service("kitchen lamp", {
            CharacteristicTypes.ON: True
        })

        Triggers events if enabled.
        """
        if name not in self.services:
            raise RuntimeError(f"Fake error: service {name!r} not found")

        service = self.services[name]

        changed = []
        for uuid, value in new_values.items():
            uuid = CharacteristicsTypes.get_uuid(uuid)

            if uuid not in service:
                raise RuntimeError(
                    f"Unexpected characteristic {uuid!r} applied to service {name!r}"
                )

            char = service[uuid]
            char.set_value(value)
            changed.append((char.service.accessory.aid, char.iid))

        self._send_events(changed)

    def update_aid_iid(self, characteristics):
        changed = []
        for (aid, iid, value) in characteristics:
            self.characteristics[(aid, iid)].set_value(value)
            changed.append((aid, iid))

        self._send_events(changed)

    def _send_events(self, changed):
        if not self.events_enabled:
            return

        event = {}
        for (aid, iid) in changed:
            if (aid, iid) not in self.pairing.subscriptions:
                continue
            event[(aid, iid)] = {"value": self.characteristics[(aid, iid)].get_value()}

        if not event:
            return

        for listener in self.pairing.listeners:
            try:
                listener(event)
            except Exception:
                _LOGGER.exception("Unhandled error when processing event")


class FakePairing(AbstractPairing):
    """
    A test fake that pretends to be a paired HomeKit accessory.

    This only contains methods and values that exist on the upstream Pairing
    class.
    """

    def __init__(self, controller, pairing_data, accessories: Accessories):
        """Create a fake pairing from an accessory model."""
        super().__init__(controller)

        self.connection = HomeKitConnection(None, "fake_host", 1234)
        self.connection.transport = "mock_transport"
        self.connection.protocol = "mock_protocol"
        self.accessories = accessories
        self.pairing_data: Dict[str, AbstractPairing] = {}
        self.available = True

        self.testing = PairingTester(self)

    async def close(self):
        pass

    async def identify(self):
        pass

    async def list_pairings(self):
        return []

    async def remove_pairing(self, pairing_id):
        pass

    async def list_accessories_and_characteristics(self):
        """Fake implementation of list_accessories_and_characteristics."""
        return self.accessories.serialize()

    async def get_characteristics(self, characteristics):
        """Fake implementation of get_characteristics."""
        if not self.available:
            raise AccessoryNotFoundError("Accessory not found")

        results = {}
        for aid, cid in characteristics:
            for accessory in self.accessories:
                if aid != accessory.aid:
                    continue
                for service in accessory.services:
                    for char in service.characteristics:
                        if char.iid != cid:
                            continue
                        results[(aid, cid)] = {"value": char.get_value()}
        return results

    async def put_characteristics(self, characteristics):
        """Fake implementation of put_characteristics."""
        self.testing.update_aid_iid(characteristics)
        return {}

    async def image(self, accessory, width, height):
        return base64.b64decode(FAKE_CAMERA_IMAGE)


class FakeController(Controller):
    """
    A test fake that pretends to be a paired HomeKit accessory.

    This only contains methods and values that exist on the upstream Controller
    class.
    """

    def __init__(self):
        """Create a Fake controller with no pairings."""
        self.pairings = {}
        self.discoveries = {}

    def add_device(self, accessories):
        device_id = "00:00:00:00:00:00"
        discovery = self.discoveries[device_id] = FakeDiscovery(
            self,
            device_id,
            accessories=accessories,
        )
        return discovery

    async def add_paired_device(self, accessories: Accessories, alias: str = None):
        discovery = self.add_device(accessories)
        finish_pairing = await discovery.start_pairing(alias or discovery.device_id)
        return await finish_pairing(discovery.pairing_code)

    async def discover_ip(self, max_seconds: int = 10):
        return self.discoveries.values()

    async def find_ip_by_device_id(self, device_id, max_seconds=10):
        return self.discoveries[device_id]

    async def remove_pairing(self, alias: str) -> None:
        del self.pairings[alias]

    def load_pairing(self, alias: str, pairing_data):
        # This assumes a test has already preseed self.pairings with a fake via
        # add_paired_device
        return self.pairings[alias]
