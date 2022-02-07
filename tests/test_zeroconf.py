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

import socket

from zeroconf.asyncio import AsyncServiceInfo

from aiohomekit.zeroconf import _service_info_is_homekit_device, get_from_properties


def test_existing_key():
    props = {"c#": "259"}
    val = get_from_properties(props, "c#")
    assert "259" == val


def test_non_existing_key_no_default():
    props = {"c#": "259"}
    val = get_from_properties(props, "s#")
    assert val is None


def test_non_existing_key_case_insensitive():
    props = {"C#": "259", "heLLo": "World"}
    val = get_from_properties(props, "c#")
    assert None is val
    val = get_from_properties(props, "c#", case_sensitive=True)
    assert None is val
    val = get_from_properties(props, "c#", case_sensitive=False)
    assert "259" == val

    val = get_from_properties(props, "HEllo", case_sensitive=False)
    assert "World" == val


def test_non_existing_key_with_default():
    props = {"c#": "259"}
    val = get_from_properties(props, "s#", default="1")
    assert "1" == val


def test_non_existing_key_with_default_non_string():
    props = {"c#": "259"}
    val = get_from_properties(props, "s#", default=1)
    assert "1" == val


def test_is_homekit_device_case_insensitive():
    desc = {
        b"C#": b"1",
        b"id": b"00:00:01:00:00:02",
        b"md": b"unittest",
        b"s#": b"1",
        b"ci": b"5",
        b"sf": b"0",
    }
    info = AsyncServiceInfo(
        "_hap._tcp.local.",
        "foo2._hap._tcp.local.",
        addresses=[socket.inet_aton("127.0.0.1")],
        port=1234,
        properties=desc,
        weight=0,
        priority=0,
    )

    assert _service_info_is_homekit_device(info)
