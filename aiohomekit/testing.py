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

from aiohomekit import exceptions
from aiohomekit.controller import Controller
from aiohomekit.controller.pairing import AbstractPairing
from aiohomekit.exceptions import AccessoryNotFoundError
from aiohomekit.model import Accessories


class FakeDiscovery(object):
    def __init__(
        self, controller: "FakeController", device_id: str, accessories: Accessories
    ):
        self.controller = controller
        self.device_id = device_id
        self.accessories = accessories

        self.pairing_code = "111-22-333"

    @property
    def info(self):
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
            "sf": self.device_id in self.controller.pairings,
        }

    async def perform_pairing(self, alias: str, pin):
        finish_pairing = await self.start_pairing(alias)
        return await finish_pairing(pin)

    async def start_pairing(self, alias: str):
        if self.device_id in self.controller.pairings:
            raise exceptions.AlreadyPairedError()

        async def finish_pairing(pairing_code):
            if pairing_code != self.pairing_code:
                raise exceptions.AuthenticationError("M4")
            pairing_data = {}
            pairing_data["AccessoryIP"] = self.info["address"]
            pairing_data["AccessoryPort"] = self.info["port"]
            pairing_data["Connection"] = "IP"

            obj = self.controller.pairings[alias] = FakePairing(
                pairing_data, self.accessories
            )
            return obj

        return finish_pairing

    async def identify(self):
        return True


class FakePairing(AbstractPairing):
    """
    A test fake that pretends to be a paired HomeKit accessory.

    This only contains methods and values that exist on the upstream Pairing
    class.
    """

    def __init__(self, pairing_data, accessories: Accessories):
        """Create a fake pairing from an accessory model."""
        self.accessories = accessories
        self.pairing_data = {}
        self.available = True

    def close(self):
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
        for aid, cid, new_val in characteristics:
            for accessory in self.accessories:
                if aid != accessory.aid:
                    continue
                for service in accessory.services:
                    for char in service.characteristics:
                        if char.iid != cid:
                            continue
                        char.set_value(new_val)
        return {}


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
            self, device_id, accessories=accessories,
        )
        return discovery

    async def add_paired_device(self, accessories: Accessories, alias: str = None):
        discovery = self.add_device(accessories)
        finish_pairing = await discovery.start_pairing(alias or discovery.device_id)
        return await finish_pairing("111-11-111")

    async def discover_ip(self, max_seconds: int = 10):
        return self.discoveries.values()

    async def find_ip_by_device_id(self, device_id, max_seconds=10):
        return self.discoveries[device_id]

    async def remove_pairing(self, alias: str) -> None:
        del self.pairings[alias]
