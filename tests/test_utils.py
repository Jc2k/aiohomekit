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

import pytest

from aiohomekit.model import Accessory
from aiohomekit.model.characteristics import (
    CharacteristicsTypes,
    InputEventValues,
    RemoteKeyValues,
)
from aiohomekit.model.services import ServicesTypes
from aiohomekit.utils import clamp_enum_to_char
from aiohomekit.uuid import normalize_uuid, shorten_uuid


def test_normalize_short_uuid():
    assert normalize_uuid("121") == "00000121-0000-1000-8000-0026BB765291"


def test_normalize_uuid():
    assert (
        normalize_uuid("00000121-0000-1000-8000-0026BB765291")
        == "00000121-0000-1000-8000-0026BB765291"
    )


def test_normalize_invalid_uuid():
    with pytest.raises(Exception):
        normalize_uuid("NOT_A_VALID_UUID")


def test_shorten_uuid():
    assert shorten_uuid("00000121-0000-1000-8000-0026BB765291") == "121"


def test_shorten_vendor_uuid():
    assert (
        shorten_uuid("00000121-0000-1000-8000-AAAAAAAAAAAA")
        == "00000121-0000-1000-8000-AAAAAAAAAAAA"
    )


def test_shorten_invalid_uuid():
    with pytest.raises(Exception):
        shorten_uuid("NOT_A_VALID_UUID")


def test_clamp_enum_valid_vals():
    a = Accessory()
    tv_service = a.add_service(service_type=ServicesTypes.TELEVISION)
    char = tv_service.add_char(
        CharacteristicsTypes.REMOTE_KEY,
        valid_values=[RemoteKeyValues.PLAY_PAUSE],
        min_value=None,
        max_value=None,
    )

    valid_vals = clamp_enum_to_char(RemoteKeyValues, char)
    assert valid_vals == {RemoteKeyValues.PLAY_PAUSE}


def test_clamp_enum_min_max():
    a = Accessory()
    tv_service = a.add_service(service_type=ServicesTypes.TELEVISION)
    char = tv_service.add_char(
        CharacteristicsTypes.REMOTE_KEY,
        valid_values=None,
        min_value=RemoteKeyValues.PLAY_PAUSE,
        max_value=RemoteKeyValues.PLAY_PAUSE,
    )

    valid_vals = clamp_enum_to_char(RemoteKeyValues, char)

    assert valid_vals == {RemoteKeyValues.PLAY_PAUSE}


def test_clamp_enum_min_max_single_press():
    a = Accessory()
    tv_service = a.add_service(service_type=ServicesTypes.STATELESS_PROGRAMMABLE_SWITCH)
    char = tv_service.add_char(
        CharacteristicsTypes.INPUT_EVENT,
        valid_values=None,
        min_value=InputEventValues.SINGLE_PRESS,
        max_value=InputEventValues.SINGLE_PRESS,
    )

    valid_vals = clamp_enum_to_char(InputEventValues, char)

    assert valid_vals == {InputEventValues.SINGLE_PRESS}


def test_clamp_enum_min_max_unclamped_button_press():
    a = Accessory()
    tv_service = a.add_service(service_type=ServicesTypes.STATELESS_PROGRAMMABLE_SWITCH)
    char = tv_service.add_char(
        CharacteristicsTypes.INPUT_EVENT,
    )

    valid_vals = clamp_enum_to_char(InputEventValues, char)

    assert valid_vals == {
        InputEventValues.SINGLE_PRESS,
        InputEventValues.DOUBLE_PRESS,
        InputEventValues.LONG_PRESS,
    }
