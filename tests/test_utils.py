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
from aiohomekit.model.feature_flags import FeatureFlags
from aiohomekit.model.services import ServicesTypes
from aiohomekit.utils import (
    clamp_enum_to_char,
    domain_supported,
    domain_to_name,
    pair_with_auth,
)
from aiohomekit.uuid import normalize_uuid, shorten_uuid


def test_normalize_short_uuid():
    assert normalize_uuid("121") == "00000121-0000-1000-8000-0026BB765291"


def test_normalize_uuid():
    assert normalize_uuid("00000121-0000-1000-8000-0026BB765291") == "00000121-0000-1000-8000-0026BB765291"


def test_normalize_uuid_coap_short():
    assert normalize_uuid("45E5011ECB4000A80FF2603DE") == "00000004-5E50-11EC-B400-0A80FF2603DE"


def test_normalize_invalid_uuid():
    with pytest.raises(Exception):
        normalize_uuid("NOT_A_VALID_UUID")


def test_shorten_uuid():
    assert shorten_uuid("00000121-0000-1000-8000-0026BB765291") == "121"


def test_shorten_vendor_uuid():
    assert shorten_uuid("00000121-0000-1000-8000-AAAAAAAAAAAA") == "00000121-0000-1000-8000-AAAAAAAAAAAA"


def test_shorten_invalid_uuid():
    with pytest.raises(Exception):
        shorten_uuid("NOT_A_VALID_UUID")


def test_clamp_enum_valid_vals(id_factory):
    a = Accessory(id_factory())
    tv_service = a.add_service(service_type=ServicesTypes.TELEVISION)
    char = tv_service.add_char(
        CharacteristicsTypes.REMOTE_KEY,
        valid_values=[RemoteKeyValues.PLAY_PAUSE],
        min_value=None,
        max_value=None,
    )

    valid_vals = clamp_enum_to_char(RemoteKeyValues, char)
    assert valid_vals == {RemoteKeyValues.PLAY_PAUSE}


def test_clamp_enum_min_max(id_factory):
    a = Accessory(id_factory())
    tv_service = a.add_service(service_type=ServicesTypes.TELEVISION)
    char = tv_service.add_char(
        CharacteristicsTypes.REMOTE_KEY,
        valid_values=None,
        min_value=RemoteKeyValues.PLAY_PAUSE,
        max_value=RemoteKeyValues.PLAY_PAUSE,
    )

    valid_vals = clamp_enum_to_char(RemoteKeyValues, char)

    assert valid_vals == {RemoteKeyValues.PLAY_PAUSE}


def test_clamp_enum_min_max_single_press(id_factory):
    a = Accessory(id_factory())
    tv_service = a.add_service(service_type=ServicesTypes.STATELESS_PROGRAMMABLE_SWITCH)
    char = tv_service.add_char(
        CharacteristicsTypes.INPUT_EVENT,
        valid_values=None,
        min_value=InputEventValues.SINGLE_PRESS,
        max_value=InputEventValues.SINGLE_PRESS,
    )

    valid_vals = clamp_enum_to_char(InputEventValues, char)

    assert valid_vals == {InputEventValues.SINGLE_PRESS}


def test_clamp_enum_min_max_unclamped_button_press(id_factory):
    a = Accessory(id_factory())
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


def test_pair_with_auth():
    # Only for FeatureFlags.SUPPORTS_APPLE_AUTHENTICATION_COPROCESSOR
    assert pair_with_auth(FeatureFlags(1)) is True
    assert pair_with_auth(FeatureFlags(2)) is False
    assert pair_with_auth(FeatureFlags(0)) is False
    assert pair_with_auth(FeatureFlags(4)) is False


def test_domain_to_name():
    assert domain_to_name("Bar._hap._tcp.local.") == "Bar"
    assert domain_to_name("Foo's Library._music._tcp.local.") == "Foo's Library"


def test_domain_supported():
    assert domain_supported("Bar._hap._tcp.local.")
    assert not domain_supported("Bar._music._tcp.local.")
