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

from collections.abc import Iterable, Iterator
from typing import TYPE_CHECKING, Any

from aiohomekit.model.characteristics import Characteristic, CharacteristicsTypes
from aiohomekit.model.characteristics.characteristic import check_convert_value
from aiohomekit.model.services.data import services
from aiohomekit.uuid import normalize_uuid

if TYPE_CHECKING:
    from aiohomekit.model import Accessory


class Characteristics:

    _characteristics: list[Characteristic]

    def __init__(self) -> None:
        self._characteristics = []
        self._iid_to_characteristic: dict[int, Characteristic] = {}

    def append(self, char: Characteristic) -> None:
        self._characteristics.append(char)
        self._iid_to_characteristic[char.iid] = char

    def get(self, iid: int) -> Characteristic:
        return self._iid_to_characteristic.get(iid)

    def __iter__(self) -> Iterator[Characteristic]:
        return iter(self._characteristics)

    def filter(self, char_types=None) -> Iterable[Characteristic]:
        matches = iter(self)

        if char_types:
            char_types = [normalize_uuid(c) for c in char_types]
            matches = filter(lambda char: char.type in char_types, matches)

        return matches

    def first(self, char_types=None) -> Characteristic:
        return next(self.filter(char_types=char_types))


class Service:

    type: str
    iid: int
    linked: list[Service]

    characteristics: Characteristics
    characteristics_by_type: dict[str, Characteristic]
    accessory: Accessory

    def __init__(
        self,
        accessory: Accessory,
        service_type: str,
        name: str | None = None,
        add_required: bool = False,
        iid: int | None = None,
    ):
        self.type = normalize_uuid(service_type)

        self.accessory = accessory
        self.iid = iid or accessory.get_next_id()
        self.characteristics = Characteristics()
        self.characteristics_by_type = {}
        self.linked = []

        if name:
            char = self.add_char(CharacteristicsTypes.NAME)
            char.set_value(name)

        if add_required:
            for required in services[self.type]["required"]:
                if required not in self.characteristics_by_type:
                    self.add_char(required)

    def has(self, char_type) -> bool:
        char_type = normalize_uuid(char_type)
        return char_type in self.characteristics_by_type

    def value(self, char_type, default_value=None) -> Any:
        char_type = normalize_uuid(char_type)

        if char_type not in self.characteristics_by_type:
            return default_value

        return self.characteristics_by_type[char_type].value

    def __getitem__(self, key) -> Characteristic:
        key = normalize_uuid(key)
        return self.characteristics_by_type[key]

    def add_char(self, char_type: str, **kwargs: Any) -> Characteristic:
        char = Characteristic(self, char_type, **kwargs)
        self.characteristics.append(char)
        self.characteristics_by_type[char.type] = char
        return char

    def get_char_by_iid(self, iid: int) -> Characteristic | None:
        """Get a characteristic by iid."""
        return self.characteristics.get(iid)

    def add_linked_service(self, service: Service) -> None:
        self.linked.append(service)

    def build_update(self, payload: dict[str, Any]) -> list[int, int, Any]:
        """
        Given a payload in the form of {CHAR_TYPE: value}, render in a form suitable to pass
        to put_characteristics using aid and iid.
        """
        result = []

        for char_type, value in payload.items():
            char = self[char_type]
            value = check_convert_value(value, char)
            result.append((self.accessory.aid, char.iid, value))

        return result

    def to_accessory_and_service_list(self):
        characteristics_list = []
        for c in self.characteristics:
            characteristics_list.append(c.to_accessory_and_service_list())
        d = {
            "iid": self.iid,
            "type": self.type,
            "characteristics": characteristics_list,
        }

        linked = [service.iid for service in self.linked]
        if linked:
            d["linked"] = linked

        return d

    @property
    def available(self) -> bool:
        return all(c.available for c in self.characteristics)
