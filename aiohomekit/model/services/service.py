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

from typing import TYPE_CHECKING

from aiohomekit.model import ToDictMixin
from aiohomekit.model.characteristics import Characteristic

if TYPE_CHECKING:
    from aiohomekit.model import Accessory


class Service(ToDictMixin):
    def __init__(self, accessory: "Accessory", service_type: str) -> None:
        self.type = service_type
        self.accessory = accessory
        self.iid = accessory.get_next_id()
        self.characteristics = []

    def add_char(self, char_type: str, **kwargs) -> Characteristic:
        char = Characteristic(self, char_type, **kwargs)
        self.characteristics.append(char)
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
