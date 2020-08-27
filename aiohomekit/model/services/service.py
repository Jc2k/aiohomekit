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

from typing import TYPE_CHECKING, Iterable, Optional

from aiohomekit.model.characteristics import Characteristic, CharacteristicsTypes
from aiohomekit.model.characteristics.characteristic import check_convert_value
from aiohomekit.model.services.data import services
from aiohomekit.model.services.service_types import ServicesTypes

from .types import ServiceShortUUID

if TYPE_CHECKING:
    from aiohomekit.model import Accessory


class Characteristics:
    def __init__(self):
        self._characteristics = []

    def append(self, char):
        self._characteristics.append(char)

    def __iter__(self):
        return iter(self._characteristics)

    def filter(self, char_types=None) -> Iterable[Characteristic]:
        matches = iter(self)

        if char_types:
            char_types = [CharacteristicsTypes.get_uuid(c) for c in char_types]
            matches = filter(lambda char: char.type in char_types, matches)

        return matches

    def first(self, char_types=None) -> Characteristic:
        return next(self.filter(char_types=char_types))


class Service:
    def __init__(
        self,
        accessory: "Accessory",
        service_type: str,
        name: Optional[str] = None,
        add_required: bool = False,
    ):
        try:
            self.type = ServicesTypes.get_uuid(service_type)
        except KeyError:
            self.type = service_type

        self.accessory = accessory
        self.iid = accessory.get_next_id()
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
        try:
            char_type = CharacteristicsTypes.get_uuid(char_type)
        except KeyError:
            pass
        return char_type in self.characteristics_by_type

    @property
    def short_type(self) -> ServiceShortUUID:
        try:
            return ServicesTypes.get_short_uuid(self.type)
        except KeyError:
            return self.type

    @property
    def type_name(self) -> str:
        try:
            return ServicesTypes.get_short(self.type)
        except KeyError:
            return None

    def value(self, char_type, default_value=None):
        try:
            char_type = CharacteristicsTypes.get_uuid(char_type)
        except KeyError:
            pass

        if char_type not in self.characteristics_by_type:
            return default_value

        return self.characteristics_by_type[char_type].value

    def __getitem__(self, key):
        try:
            key = CharacteristicsTypes.get_uuid(key)
        except KeyError:
            pass
        return self.characteristics_by_type[key]

    def add_char(self, char_type: str, **kwargs) -> Characteristic:
        char = Characteristic(self, char_type, **kwargs)
        self.characteristics.append(char)
        self.characteristics_by_type[char.type] = char
        return char

    def add_linked_service(self, service: "Service"):
        self.linked.append(service)

    def build_update(self, payload):
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
