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
from __future__ import annotations

import base64
from collections.abc import AsyncIterable
from dataclasses import dataclass
from datetime import timedelta
import logging

from aiohomekit import exceptions
from aiohomekit.characteristic_cache import CharacteristicCacheMemory
from aiohomekit.controller.abstract import (
    AbstractController,
    AbstractDiscovery,
    AbstractPairing,
    AbstractPairingData,
    FinishPairing,
)
from aiohomekit.exceptions import AccessoryNotFoundError
from aiohomekit.model import Accessories, AccessoriesState, Transport
from aiohomekit.model.categories import Categories
from aiohomekit.model.characteristics import CharacteristicsTypes
from aiohomekit.model.status_flags import StatusFlags
from aiohomekit.protocol.statuscodes import HapStatusCode
from aiohomekit.uuid import normalize_uuid

_LOGGER = logging.getLogger(__name__)

FAKE_CAMERA_IMAGE = (
    b"/9j/2wBDAAMCAgICAgMCAgIDAwMDBAYEBAQEBAgGBgUGCQgKCgkICQkKDA8MCgsOCwkJDRE"
    b"NDg8QEBEQCgwSExIQEw8QEBD/yQALCAABAAEBAREA/8wABgAQEAX/2gAIAQEAAD8A0s8g/9k="
)


@dataclass
class FakeDescription:

    name: str = "TestDevice"
    id: str = "00:00:00:00:00:00"
    model: str = "TestDevice"
    status_flags: StatusFlags = StatusFlags.UNPAIRED
    config_num: int = 1
    state_num: int = 1
    category: Categories = Categories.OTHER


class FakeDiscovery(AbstractDiscovery):

    description = FakeDescription()

    def __init__(
        self, controller: FakeController, device_id: str, accessories: Accessories
    ):
        self.controller = controller
        self.accessories = accessories

        self.pairing_code = "111-22-333"

    @property
    def status_flags(self) -> StatusFlags:
        if self.description.id not in self.controller.pairings:
            return StatusFlags.UNPAIRED
        return StatusFlags(0)

    async def async_start_pairing(self, alias: str) -> FinishPairing:
        if self.description.id in self.controller.pairings:
            raise exceptions.AlreadyPairedError(f"{self.description.id} already paired")

        async def finish_pairing(pairing_code: str) -> FakePairing:
            if pairing_code != self.pairing_code:
                raise exceptions.AuthenticationError("M4")

            discovery = self.controller.discoveries[self.description.id]
            discovery.description = FakeDescription(status_flags=0)

            pairing_data = {}
            # pairing_data["AccessoryIP"] = self.address
            # pairing_data["AccessoryPort"] = self.port
            pairing_data["AccessoryPairingID"] = discovery.description.id
            pairing_data["Connection"] = "Fake"

            obj = FakePairing(self.controller, pairing_data, self.accessories)
            self.controller.aliases[alias] = obj
            self.controller.pairings[discovery.description.id] = obj

            return obj

        return finish_pairing

    async def async_identify(self) -> None:
        """Trigger an identify routinue."""


class PairingTester:
    """
    A holding class for test-only helpers.

    This is done to minimize the difference between a FakePairing and a real pairing.
    """

    def __init__(self, pairing: FakePairing, accessories: Accessories):
        self.pairing = pairing
        self.events_enabled = True

        self.characteristics = {}
        self.services = {}

        for accessory in accessories:
            for service in accessory.services:
                service_map = {}
                for char in service.characteristics:
                    self.characteristics[(accessory.aid, char.iid)] = char
                    service_map[char.type] = char
                    if char.type == CharacteristicsTypes.NAME:
                        self.services[char.get_value()] = service_map

    def set_events_enabled(self, value):
        self.events_enabled = value

    def update_named_service(self, name: str, new_values):
        """
        Finds a named service then sets characteristics by type.

        pairing.test.update_named_service("kitchen lamp", {
            CharacteristicsTypes.ON: True
        })

        Triggers events if enabled.
        """
        if name not in self.services:
            raise RuntimeError(f"Fake error: service {name!r} not found")

        service = self.services[name]

        changed = []
        for uuid, value in new_values.items():
            uuid = normalize_uuid(uuid)

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

    def __init__(
        self,
        controller: AbstractController,
        pairing_data: AbstractPairingData,
        accessories: Accessories,
    ) -> None:
        """Create a fake pairing from an accessory model."""
        super().__init__(controller, pairing_data)

        self._initial_accessories_state = AccessoriesState(accessories, 0)

        self._accessories_state = None
        self.pairing_data: dict[str, str] = {}
        self.available = True

        self.testing = PairingTester(self, accessories)

    @property
    def is_connected(self) -> bool:
        return True

    @property
    def is_available(self) -> bool:
        return True

    @property
    def transport(self) -> Transport:
        return Transport.IP

    @property
    def poll_interval(self) -> timedelta:
        """Returns how often the device should be polled."""
        return timedelta(minutes=1)

    async def close(self):
        """Close the connection."""

    def _ensure_connected(self):
        if not self.available:
            raise AccessoryNotFoundError("Accessory not found")
        if not self._accessories_state:
            self._accessories_state = self._initial_accessories_state
            self._update_accessories_state_cache()

    async def identify(self):
        """Identify the accessory."""
        self._ensure_connected()

    async def list_pairings(self):
        """List pairing."""
        return []

    async def remove_pairing(self, pairing_id):
        """Remove a pairing."""
        self._ensure_connected()

    async def async_populate_accessories_state(
        self, force_update: bool = False, attempts: int | None = None
    ) -> bool:
        """Populate the state of all accessories.

        This method should try not to fetch all the accessories unless
        we know the config num is out of date or force_update is True
        """
        self._ensure_connected()
        return True

    async def _process_config_changed(self, config_num: int) -> None:
        await self.list_accessories_and_characteristics()
        self._accessories_state = AccessoriesState(
            self._accessories_state.accessories, config_num
        )
        self._callback_and_save_config_changed(config_num)

    async def _process_disconnected_events(self):
        """Process any events that happened while we were disconnected."""

    async def list_accessories_and_characteristics(self):
        """Fake implementation of list_accessories_and_characteristics."""
        self._ensure_connected()
        return self.accessories.serialize()

    async def get_characteristics(self, characteristics):
        """Fake implementation of get_characteristics."""
        self._ensure_connected()

        results = {}
        for aid, cid in characteristics:
            accessory = self.accessories.aid(aid)
            char = accessory.characteristics.iid(cid)
            if char.status != HapStatusCode.SUCCESS:
                results[(aid, cid)] = {"status": char.status.value}
                continue
            results[(aid, cid)] = {"value": char.get_value()}

        return results

    async def put_characteristics(self, characteristics):
        """Fake implementation of put_characteristics."""
        self._ensure_connected()

        filtered = []
        results = {}
        for (aid, cid, value) in characteristics:
            accessory = self.accessories.aid(aid)
            char = accessory.characteristics.iid(cid)
            if char.status != HapStatusCode.SUCCESS:
                results[(aid, cid)] = {"status": char.status.value}
                continue
            filtered.append((aid, cid, value))
        self.testing.update_aid_iid(filtered)
        return results

    async def image(self, accessory: int, width: int, height: int) -> bytes:
        self._ensure_connected()

        return base64.b64decode(FAKE_CAMERA_IMAGE)


class FakeController(AbstractController):
    """
    A test fake that pretends to be a paired HomeKit accessory.

    This only contains methods and values that exist on the upstream Controller
    class.
    """

    started: bool
    discoveries: dict[str, FakeDiscovery]
    pairings: dict[str, FakePairing]
    aliases: dict[str, FakePairing]

    def __init__(
        self, async_zeroconf_instance=None, char_cache=None, bleak_scanner_instance=None
    ):
        super().__init__(char_cache=char_cache or CharacteristicCacheMemory())

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
        finish_pairing = await discovery.async_start_pairing(
            alias or discovery.description.id
        )
        return await finish_pairing(discovery.pairing_code)

    async def async_start(self) -> None:
        self.started = True

    async def async_stop(self) -> None:
        self.started = False

    async def async_discover(
        self, max_seconds: int = 10
    ) -> AsyncIterable[AbstractDiscovery]:
        for discovery in self.discoveries.values():
            yield discovery

    async def async_find(self, device_id, max_seconds=10) -> AbstractDiscovery:
        try:
            return self.discoveries[device_id]
        except KeyError:
            raise AccessoryNotFoundError(device_id)

    async def remove_pairing(self, alias: str) -> None:
        pairing = self.aliases[alias]
        del self.pairings[self.aliases[alias].id]
        del self.aliases[alias]
        self._char_cache.async_delete_map(pairing.id)

    def load_pairing(self, alias: str, pairing_data):
        # This assumes a test has already preseed self.pairings with a fake via
        # add_paired_device
        return self.aliases[alias]
