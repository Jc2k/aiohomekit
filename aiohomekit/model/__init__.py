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

from collections.abc import Iterator
from dataclasses import dataclass
from enum import Enum
from typing import Any

from aiohomekit import hkjson
from aiohomekit.protocol.statuscodes import to_status_code
from aiohomekit.uuid import normalize_uuid

from . import entity_map
from .categories import Categories
from .characteristics import (
    EVENT_CHARACTERISTICS,
    Characteristic,
    CharacteristicFormats,
    CharacteristicPermissions,
    CharacteristicsTypes,
)
from .feature_flags import FeatureFlags
from .services import Service, ServicesTypes

__all__ = [
    "Accessory",
    "Categories",
    "CharacteristicFormats",
    "CharacteristicPermissions",
    "FeatureFlags",
    "Service",
    "ServiceTypes",
    "Transport",
]

NEEDS_POLLINGS_CHARS = {
    CharacteristicsTypes.VENDOR_EVE_ENERGY_WATT,
    CharacteristicsTypes.VENDOR_CONNECTSENSE_ENERGY_WATT,
}


class Transport(Enum):
    BLE = "ble"
    COAP = "coap"
    IP = "ip"


class Services:
    """Represents a list of HomeKit services."""

    def __init__(self):
        """Initialize a new list of services."""
        self._services: list[Service] = []
        self._iid_to_service: dict[int, Service] = {}
        self._type_to_service: dict[str, Service] = {}

    def __iter__(self) -> Iterator[Service]:
        """Iterate over all services."""
        return iter(self._services)

    def iid(self, iid: int) -> Service:
        """Return the service with the given iid, raising KeyError if it does not exist."""
        return self._iid_to_service[iid]

    def iid_or_none(self, iid: int) -> Service | None:
        """Return the service with the given iid or None if it does not exist."""
        return self._iid_to_service.get(iid)

    def get_char_by_iid(self, iid: int) -> Characteristic | None:
        """Get a characteristic by iid."""
        for service in self._services:
            if char := service.get_char_by_iid(iid):
                return char
        return None

    def filter(
        self,
        *,
        service_type: str = None,
        characteristics: dict[str, str] = None,
        parent_service: Service = None,
        child_service: Service = None,
        order_by: list[str] | None = None,
    ) -> Iterator[Service]:
        """Filter services by type and characteristics."""
        matches = iter(self._services)

        if service_type:
            service_type = normalize_uuid(service_type)
            matches = filter(lambda service: service.type == service_type, matches)

        if characteristics:
            for characteristic, value in characteristics.items():
                matches = filter(lambda service: service.value(characteristic) == value, matches)

        if parent_service:
            matches = filter(lambda service: service in parent_service.linked, matches)

        if child_service:
            matches = filter(lambda service: child_service in service.linked, matches)

        if order_by:
            matches = sorted(
                matches,
                key=lambda service: tuple(service.value(char_type) for char_type in order_by),
            )

        return matches

    def first(
        self,
        *,
        service_type: str = None,
        characteristics: dict[str, str] = None,
        parent_service: Service = None,
        child_service: Service = None,
    ) -> Service | None:
        """Get the first service."""
        if (
            service_type is not None
            and characteristics is None
            and parent_service is None
            and child_service is None
        ):
            return self._type_to_service.get(normalize_uuid(service_type))

        try:
            return next(
                self.filter(
                    service_type=service_type,
                    characteristics=characteristics,
                    parent_service=parent_service,
                    child_service=child_service,
                )
            )
        except StopIteration:
            return None

    def append(self, service: Service) -> None:
        """Add a service to the list of services."""
        self._services.append(service)
        self._iid_to_service[service.iid] = service
        if service.type not in self._type_to_service:
            self._type_to_service[service.type] = service


class Characteristics:
    """Represents a list of HomeKit characteristics."""

    def __init__(self, services: Services) -> None:
        """Initialize a new list of characteristics."""
        self._services = services

    def iid(self, iid: int) -> Characteristic | None:
        """Return the characteristic with the given iid, return None if it does not exist."""
        return self._services.get_char_by_iid(iid)


class Accessory:
    """Represents a HomeKit accessory."""

    def __init__(self, aid: int) -> None:
        """Initialize a new accessory."""
        self.aid = aid
        self._next_id = 0
        self.services = Services()
        self.characteristics = Characteristics(self.services)
        self._accessory_information: Service | None = None

    @classmethod
    def create_with_info(
        cls,
        aid: int,
        name: str,
        manufacturer: str,
        model: str,
        serial_number: str,
        firmware_revision: str,
    ) -> Accessory:
        """Create an accessory with the required services for HomeKit.

        This method should only be used for testing purposes as it assigns
        the next available ids to the accessory and services.
        """
        self = cls(aid)

        accessory_info = self.add_service(ServicesTypes.ACCESSORY_INFORMATION)
        accessory_info.add_char(CharacteristicsTypes.IDENTIFY, description="Identify")
        accessory_info.add_char(CharacteristicsTypes.NAME, value=name)
        accessory_info.add_char(CharacteristicsTypes.MANUFACTURER, value=manufacturer)
        accessory_info.add_char(CharacteristicsTypes.MODEL, value=model)
        accessory_info.add_char(CharacteristicsTypes.SERIAL_NUMBER, value=serial_number)
        accessory_info.add_char(CharacteristicsTypes.FIRMWARE_REVISION, value=firmware_revision)

        return self

    @property
    def accessory_information(self) -> Service:
        """Returns the ACCESSORY_INFORMATION service for this accessory."""
        if self._accessory_information is None:
            self._accessory_information = self.services.first(
                service_type=ServicesTypes.ACCESSORY_INFORMATION
            )
        return self._accessory_information

    @property
    def name(self) -> str:
        """Return the name of the accessory."""
        return self.accessory_information.value(CharacteristicsTypes.NAME, "")

    @property
    def manufacturer(self) -> str:
        """Return the manufacturer of the accessory."""
        return self.accessory_information.value(CharacteristicsTypes.MANUFACTURER, "")

    @property
    def model(self) -> str | None:
        """Return the model of the accessory."""
        return self.accessory_information.value(CharacteristicsTypes.MODEL, "")

    @property
    def serial_number(self) -> str:
        """Return the serial number of the accessory."""
        return self.accessory_information.value(CharacteristicsTypes.SERIAL_NUMBER, "")

    @property
    def firmware_revision(self) -> str:
        """Return the firmware revision of the accessory."""
        return self.accessory_information.value(CharacteristicsTypes.FIRMWARE_REVISION, "")

    @property
    def hardware_revision(self) -> str:
        """Return the hardware revision of the accessory."""
        return self.accessory_information.value(CharacteristicsTypes.HARDWARE_REVISION, "")

    @property
    def available(self) -> bool:
        """Return True if the accessory is available."""
        return all(s.available for s in self.services)

    @property
    def needs_polling(self) -> bool:
        """Check if there are any chars that need polling.

        Currently this is only used for BLE devices that have
        energy consumption characteristics.
        """
        for s in self.services:
            for c in s.characteristics:
                if c.type in NEEDS_POLLINGS_CHARS:
                    return True
        return False

    @classmethod
    def create_from_dict(cls, data: dict[str, Any]) -> Accessory:
        """Create an accessory from a dict."""
        accessory = cls(data["aid"])

        for service_data in data["services"]:
            service = accessory.add_service(service_data["type"], iid=service_data["iid"], add_required=False)
            for char_data in service_data["characteristics"]:
                kwargs = {
                    "perms": char_data["perms"],
                }
                if "format" in char_data:
                    kwargs["format"] = char_data["format"]
                if "description" in char_data:
                    kwargs["description"] = char_data["description"]
                if "minValue" in char_data:
                    kwargs["min_value"] = char_data["minValue"]
                if "maxValue" in char_data:
                    kwargs["max_value"] = char_data["maxValue"]
                if "valid-values" in char_data:
                    kwargs["valid_values"] = char_data["valid-values"]
                if "unit" in char_data:
                    kwargs["unit"] = char_data["unit"]
                if "minStep" in char_data:
                    kwargs["min_step"] = char_data["minStep"]
                if "maxLen" in char_data:
                    kwargs["max_len"] = char_data["maxLen"]
                if "handle" in char_data:
                    kwargs["handle"] = char_data["handle"]
                if "broadcast_events" in char_data:
                    kwargs["broadcast_events"] = char_data["broadcast_events"]
                if "disconnected_events" in char_data:
                    kwargs["disconnected_events"] = char_data["disconnected_events"]

                char = service.add_char(char_data["type"], iid=char_data["iid"], **kwargs)
                if char_data.get("value") is not None:
                    char.set_value(char_data["value"])

        for service_data in data["services"]:
            for linked_service in service_data.get("linked", []):
                # https://github.com/home-assistant/core/issues/100160
                # The Schlage Encode Plus can contain a 0 in this list which we have to ignore
                if linked_service:
                    accessory.services.iid(service_data["iid"]).add_linked_service(
                        accessory.services.iid(linked_service)
                    )

        return accessory

    def get_next_id(self) -> int:
        """Return the next available id for a service."""
        self._next_id += 1
        return self._next_id

    def add_service(
        self,
        service_type: str,
        name: str | None = None,
        add_required: bool = False,
        iid: int | None = None,
    ) -> Service:
        """Add a service to the accessory."""
        service = Service(self, service_type, name=name, add_required=add_required, iid=iid)
        self.services.append(service)
        return service

    def to_accessory_and_service_list(self) -> dict[str, Any]:
        """Serialize the accessory to a dict."""
        return {
            "aid": self.aid,
            "services": [s.to_accessory_and_service_list() for s in self.services],
        }


class Accessories:
    """Represents a list of HomeKit accessories."""

    accessories: list[Accessory]

    def __init__(self) -> None:
        """Initialize a new list of accessories."""
        self.accessories = []
        self._aid_to_accessory: dict[int, Accessory] = {}

    def __iter__(self) -> Iterator[Accessory]:
        return iter(self.accessories)

    def __getitem__(self, idx: int) -> Accessory:
        return self.accessories[idx]

    @classmethod
    def from_file(cls, path) -> Accessories:
        with open(path, encoding="utf-8") as fp:
            return cls.from_list(hkjson.loads(fp.read()))

    @classmethod
    def from_list(cls, accessories: entity_map.Accesories) -> Accessories:
        self = cls()
        for accessory in accessories:
            self.add_accessory(Accessory.create_from_dict(accessory))
        return self

    def add_accessory(self, accessory: Accessory) -> None:
        """Add an accessory to the list of accessories."""
        self.accessories.append(accessory)
        self._aid_to_accessory[accessory.aid] = accessory

    def serialize(self) -> entity_map.Accesories:
        """Serialize the accessories to a list of dicts."""
        return [a.to_accessory_and_service_list() for a in self.accessories]

    def to_accessory_and_service_list(self) -> dict[str, entity_map.Accesories]:
        return hkjson.dumps({"accessories": self.serialize()})

    def aid(self, aid: int) -> Accessory:
        """Return the accessory with the given aid, raising KeyError if it does not exist."""
        return self._aid_to_accessory[aid]

    def aid_or_none(self, aid: int) -> Accessory | None:
        """Return the accessory with the given aid or None if it does not exist."""
        return self._aid_to_accessory.get(aid)

    def has_aid(self, aid: int) -> bool:
        """Return True if the given aid exists."""
        return aid in self._aid_to_accessory

    def process_changes(self, changes: dict[tuple[int, int], dict[str, Any]]) -> set[tuple[int, int]]:
        """Process changes from a HomeKit controller.

        Returns a set of the changes that were applied.
        """
        changed: set[tuple[int, int]] = set()
        for aid_iid, value in changes.items():
            (aid, iid) = aid_iid
            if not (char := self.aid(aid).characteristics.iid(iid)):
                continue

            if "value" in value:
                if char.set_value(value["value"]) or char.type in EVENT_CHARACTERISTICS:
                    changed.add(aid_iid)

            previous_status = char.status
            char.status = to_status_code(value.get("status", 0))
            if previous_status != char.status:
                changed.add(aid_iid)

        return changed


@dataclass
class AccessoriesState:
    accessories: Accessories
    config_num: int
    broadcast_key: bytes | None = None
    state_num: int | None = None
