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

from aiohomekit.model.characteristics.characteristic_types import CharacteristicsTypes


def test_get_uuid_forward():
    assert (
        CharacteristicsTypes.get_uuid(CharacteristicsTypes.ON)
        == "00000025-0000-1000-8000-0026BB765291"
    )


def test_get_uuid_full_uuid():
    assert "0000006D-0000-1000-8000-0026BB765291" == CharacteristicsTypes.get_uuid(
        "0000006D-0000-1000-8000-0026BB765291"
    )


def test_get_uuid_short_uuid():
    assert "0000006D-0000-1000-8000-0026BB765291" == CharacteristicsTypes.get_uuid("6D")


def test_get_uuid_unknown_2():
    with pytest.raises(KeyError):
        CharacteristicsTypes.get_uuid("UNKNOWN-UNKNOWN")


def test_get_short_uuid_full_uuid():
    assert "6D" == CharacteristicsTypes.get_short_uuid(
        "0000006D-0000-1000-8000-0026BB765291"
    )


def test_get_short_uuid_short():
    assert "6D" == CharacteristicsTypes.get_short_uuid("6D")


def test_get_short_uuid_passthrough():
    assert (
        "0000006D-1234-1234-1234-012345678901"
        == CharacteristicsTypes.get_short_uuid("0000006D-1234-1234-1234-012345678901")
    )
