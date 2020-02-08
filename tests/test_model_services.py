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

from aiohomekit.model.services import ServicesTypes


def test_getitem_forward():
    assert ServicesTypes["3E"] == "public.hap.service.accessory-information"


def test_getitem_reverse():
    assert ServicesTypes["public.hap.service.accessory-information"] == "3E"


def test_getitem_notfound():
    assert ServicesTypes["1337"] == "Unknown Service: 1337"


def test_get_short():
    assert (
        ServicesTypes.get_short("00000086-0000-1000-8000-0026BB765291") == "occupancy"
    )


def test_get_short_lowercase():
    assert (
        ServicesTypes.get_short("00000086-0000-1000-8000-0026bb765291") == "occupancy"
    )


def test_get_short_no_baseid():
    assert (
        ServicesTypes.get_short("00000023-0000-1000-8000-NOTBASEID")
        == "Unknown Service: 00000023-0000-1000-8000-NOTBASEID"
    )


def test_get_short_no_service():
    assert (
        ServicesTypes.get_short("00000023-0000-1000-8000-0026BB765291")
        == "Unknown Service: 00000023-0000-1000-8000-0026BB765291"
    )


def test_get_uuid():
    assert (
        ServicesTypes.get_uuid("public.hap.service.doorbell")
        == "00000121-0000-1000-8000-0026BB765291"
    )


def test_get_uuid_no_service():
    with pytest.raises(Exception):
        ServicesTypes.get_uuid("public.hap.service.NO_A_SERVICE")
