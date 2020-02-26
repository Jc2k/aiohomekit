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

from typing import TYPE_CHECKING, Optional

from aiohomekit.model import ToDictMixin
from aiohomekit.model.characteristics import Characteristic, CharacteristicsTypes
from aiohomekit.model.services.data import services
from aiohomekit.model.services.service_types import ServicesTypes

if TYPE_CHECKING:
    from aiohomekit.model import Accessory


class Service(ToDictMixin):
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
        self.characteristics = []
        self.characteristics_by_type = {}

        if name:
            char = self.add_char(CharacteristicsTypes.NAME)
            char.value = name

        if add_required:
            for required in services[self.type]["required"]:
                if required not in self.characteristics_by_type:
                    self.add_char(required)

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

    def to_accessory_and_service_list(self):
        characteristics_list = []
        for c in self.characteristics:
            characteristics_list.append(c.to_accessory_and_service_list())
        d = {
            "iid": self.iid,
            "type": self.type,
            "characteristics": characteristics_list,
        }
        return d
