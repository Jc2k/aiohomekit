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

from aiohomekit.model import Accessory
from aiohomekit.model.services import ServicesTypes


def test_hue_bridge():
    a = Accessory.setup_accessories_from_file("tests/fixtures/hue_bridge.json")

    service = a[0].services.one(service_type=ServicesTypes.ACCESSORY_INFORMATION)
    char = service.characteristics[0]
    assert char.iid == 37
    assert char.perms == ["pr"]
    assert char.format == "string"
    assert char.value == "Hue dimmer switch"
    assert char.description == "Name"
    assert char.maxLen == 64


def test_linked_services():
    a = Accessory.setup_accessories_from_file("tests/fixtures/hue_bridge.json")

    service = a[0].services.one(
        service_type=ServicesTypes.STATELESS_PROGRAMMABLE_SWITCH
    )
    assert len(service.linked) > 0
    assert service.linked[0].short_type == ServicesTypes.SERVICE_LABEL
