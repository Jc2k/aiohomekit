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

import json
from typing import Any, Dict, List, Optional

from .categories import Categories
from .characteristics import (
    CharacteristicFormats,
    CharacteristicPermissions,
    CharacteristicsTypes,
)
from .feature_flags import FeatureFlags
from .mixin import ToDictMixin, get_id
from .services import Service, ServicesTypes

__all__ = [
    "Categories",
    "CharacteristicPermissions",
    "CharacteristicFormats",
    "FeatureFlags",
    "Accessory",
]


class Accessory(ToDictMixin):
    def __init__(
        self,
        name: str,
        manufacturer: str,
        model: str,
        serial_number: str,
        firmware_revision: str,
    ) -> None:
        self.aid = get_id()
        self.services = []

        self._next_id = 0

        accessory_info = self.add_service(ServicesTypes.ACCESSORY_INFORMATION)
        accessory_info.add_char(CharacteristicsTypes.IDENTIFY, description="Identify")
        accessory_info.add_char(CharacteristicsTypes.NAME, value=name)
        accessory_info.add_char(CharacteristicsTypes.MANUFACTURER, value=manufacturer)
        accessory_info.add_char(CharacteristicsTypes.MODEL, value=model)
        accessory_info.add_char(CharacteristicsTypes.SERIAL_NUMBER, value=serial_number)
        accessory_info.add_char(
            CharacteristicsTypes.FIRMWARE_REVISION, value=firmware_revision
        )

    @classmethod
    def setup_accessories_from_file(cls, path: str) -> List["Accessory"]:
        with open(path, "r") as fp:
            accessories_json = json.load(fp)
        return cls.setup_accessories_from_list(accessories_json)

    @classmethod
    def setup_accessories_from_list(
        cls, data: List[Dict[str, Any]]
    ) -> List["Accessory"]:
        accessories = []
        for accessory_data in data:
            accessories.append(cls.setup_from_dict(accessory_data))
        return accessories

    @classmethod
    def setup_from_dict(cls, data: Dict[str, Any]) -> "Accessory":
        accessory = cls("Name", "Mfr", "Model", "0001", "0.1")
        accessory.services = []
        accessory.aid = data["aid"]

        for service_data in data["services"]:
            service = accessory.add_service(service_data["type"], add_required=False)
            service.iid = service_data["iid"]

            for char_data in service_data["characteristics"]:
                kwargs = {
                    "perms": char_data["perms"],
                    "format": char_data["format"],
                }

                if "description" in char_data:
                    kwargs["description"] = char_data["description"]
                if "value" in char_data:
                    kwargs["value"] = char_data["value"]
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

                char = service.add_char(char_data["type"], **kwargs)
                char.iid = char_data["iid"]

        return accessory

    def get_next_id(self) -> int:
        self._next_id += 1
        return self._next_id

    def add_service(
        self, service_type: str, name: Optional[str] = None, add_required: bool = False
    ) -> Service:
        service = Service(self, service_type, name=name, add_required=add_required)
        self.services.append(service)
        return service

    def to_accessory_and_service_list(self):
        services_list = []
        for s in self.services:
            services_list.append(s.to_accessory_and_service_list())
        d = {"aid": self.aid, "services": services_list}
        return d


class Accessories(ToDictMixin):
    def __init__(self) -> None:
        self.accessories = []

    def __iter__(self):
        return iter(self.accessories)

    @classmethod
    def from_file(cls, path):
        self = cls()
        for accessory in Accessory.setup_accessories_from_file(path):
            self.add_accessory(accessory)
        return self

    def add_accessory(self, accessory: Accessory) -> None:
        self.accessories.append(accessory)

    def serialize(self):
        accessories_list = []
        for a in self.accessories:
            accessories_list.append(a.to_accessory_and_service_list())
        return accessories_list

    def to_accessory_and_service_list(self):
        d = {"accessories": self.serialize()}
        return json.dumps(d)
