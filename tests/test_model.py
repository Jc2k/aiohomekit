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

from aiohomekit.model import Accessories
from aiohomekit.model.characteristics import CharacteristicsTypes
from aiohomekit.model.services import ServicesTypes


def test_hue_bridge():
    a = Accessories.from_file("tests/fixtures/hue_bridge.json").aid(6623462389072572)
    assert a.name == "Hue dimmer switch"
    assert a.model == "RWL021"
    assert a.manufacturer == "Philips"
    assert a.serial_number == "6623462389072572"
    assert a.firmware_revision == "45.1.17846"

    service = a.services.first(service_type=ServicesTypes.ACCESSORY_INFORMATION)
    assert service.type_name == "accessory-information"

    char = next(iter(service.characteristics))
    assert char.iid == 37
    assert char.type_name == "name"
    assert char.perms == ["pr"]
    assert char.format == "string"
    assert char.value == "Hue dimmer switch"
    assert char.description == "Name"
    assert char.maxLen == 64

    assert service.has_characteristic(char.type)


def test_linked_services():
    a = Accessories.from_file("tests/fixtures/hue_bridge.json").aid(6623462389072572)

    service = a.services.first(service_type=ServicesTypes.STATELESS_PROGRAMMABLE_SWITCH)
    assert len(service.linked) > 0
    assert service.linked[0].short_type == ServicesTypes.SERVICE_LABEL


def test_get_by_name():
    name = "Hue dimmer switch button 3"
    a = Accessories.from_file("tests/fixtures/hue_bridge.json").aid(6623462389072572)

    service = a.services.first(
        service_type=ServicesTypes.STATELESS_PROGRAMMABLE_SWITCH,
        characteristics={CharacteristicsTypes.NAME: name},
    )

    assert service[CharacteristicsTypes.NAME].value == name


def test_get_by_characteristic_types():
    name = "Hue dimmer switch button 3"

    a = Accessories.from_file("tests/fixtures/hue_bridge.json").aid(6623462389072572)

    service = a.services.first(
        service_type=ServicesTypes.STATELESS_PROGRAMMABLE_SWITCH,
        characteristics={CharacteristicsTypes.NAME: name},
    )

    char = service.characteristics.first(char_types=[CharacteristicsTypes.NAME])

    assert char.value == name


def test_get_by_linked():
    name = "Hue dimmer switch button 3"
    a = Accessories.from_file("tests/fixtures/hue_bridge.json").aid(6623462389072572)

    switch = a.services.first(
        service_type=ServicesTypes.STATELESS_PROGRAMMABLE_SWITCH,
        characteristics={CharacteristicsTypes.NAME: name},
    )

    service_label = a.services.first(parent_service=switch)
    assert service_label[CharacteristicsTypes.SERVICE_LABEL_NAMESPACE].value == 1

    switch = a.services.first(
        service_type=ServicesTypes.STATELESS_PROGRAMMABLE_SWITCH,
        characteristics={CharacteristicsTypes.NAME: name},
        child_service=service_label,
    )

    assert switch[CharacteristicsTypes.NAME].value == "Hue dimmer switch button 3"


def test_order_by():
    a = Accessories.from_file("tests/fixtures/hue_bridge.json").aid(6623462389072572)

    buttons = a.services.filter(
        service_type=ServicesTypes.STATELESS_PROGRAMMABLE_SWITCH,
        order_by=(CharacteristicsTypes.SERVICE_LABEL_INDEX, CharacteristicsTypes.NAME),
    )

    assert buttons[0].value(CharacteristicsTypes.SERVICE_LABEL_INDEX) == 1
    assert buttons[1].value(CharacteristicsTypes.SERVICE_LABEL_INDEX) == 2
    assert buttons[2].value(CharacteristicsTypes.SERVICE_LABEL_INDEX) == 3
    assert buttons[3].value(CharacteristicsTypes.SERVICE_LABEL_INDEX) == 4


def test_process_changes():
    accessories = Accessories.from_file("tests/fixtures/koogeek_ls1.json")

    on_char = accessories.aid(1).characteristics.iid(8)
    assert on_char.value is False

    accessories.process_changes({(1, 8): {"value": True}})

    assert on_char.value is True


def test_valid_vals_preserved():
    a = Accessories.from_file("tests/fixtures/aqara_gateway.json").aid(1)
    char = a.characteristics.iid(66307)
    assert char.valid_values == [1, 3, 4]


def test_build_update():
    name = "Hue dimmer switch button 3"

    a = Accessories.from_file("tests/fixtures/hue_bridge.json").aid(6623462389072572)

    service = a.services.first(
        service_type=ServicesTypes.STATELESS_PROGRAMMABLE_SWITCH,
        characteristics={CharacteristicsTypes.NAME: name},
    )

    payload = service.build_update({CharacteristicsTypes.NAME: "Fred"})

    assert payload == [(6623462389072572, 588410716196, "Fred")]
