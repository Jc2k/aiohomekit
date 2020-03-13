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
from unittest.mock import patch

import pytest
from zeroconf import ServiceInfo

from aiohomekit.exceptions import AccessoryNotFoundError
from aiohomekit.model.feature_flags import FeatureFlags
from aiohomekit.zeroconf import (
    async_find_device_ip_and_port,
    discover_homekit_devices,
    get_from_properties,
)


@pytest.fixture
def mock_zeroconf():
    """Mock zeroconf."""

    def browser(zeroconf, service, handler):
        handler.add_service(zeroconf, service, f"name.{service}")

    with patch("aiohomekit.zeroconf.ServiceBrowser") as mock_browser:
        mock_browser.side_effect = browser

        with patch("aiohomekit.zeroconf.Zeroconf") as mock_zc:
            yield mock_zc.return_value


async def test_find_no_device(mock_zeroconf):
    with pytest.raises(AccessoryNotFoundError):
        await async_find_device_ip_and_port("00:00:00:00:00:00", 0)


async def test_find_with_device(mock_zeroconf):
    desc = {b"id": b"00:00:02:00:00:02"}
    info = ServiceInfo(
        "_hap._tcp.local.",
        "foo1._hap._tcp.local.",
        addresses=[socket.inet_aton("127.0.0.1")],
        port=1234,
        properties=desc,
        weight=0,
        priority=0,
    )
    mock_zeroconf.get_service_info.return_value = info

    result = await async_find_device_ip_and_port("00:00:02:00:00:02", 0)
    assert result == ("127.0.0.1", 1234)


def test_discover_homekit_devices(mock_zeroconf):
    desc = {
        b"c#": b"1",
        b"id": b"00:00:01:00:00:02",
        b"md": b"unittest",
        b"s#": b"1",
        b"ci": b"5",
        b"sf": b"0",
    }
    info = ServiceInfo(
        "_hap._tcp.local.",
        "foo2._hap._tcp.local.",
        addresses=[socket.inet_aton("127.0.0.1")],
        port=1234,
        properties=desc,
        weight=0,
        priority=0,
    )
    mock_zeroconf.get_service_info.return_value = info

    result = discover_homekit_devices(max_seconds=0)

    assert result == [
        {
            "address": "127.0.0.1",
            "c#": "1",
            "category": "Lightbulb",
            "ci": "5",
            "ff": 0,
            "flags": FeatureFlags(0),
            "id": "00:00:01:00:00:02",
            "md": "unittest",
            "name": "foo2._hap._tcp.local.",
            "port": 1234,
            "pv": "1.0",
            "s#": "1",
            "sf": "0",
            "statusflags": "Accessory has been paired.",
        }
    ]


def test_discover_homekit_devices_missing_c(mock_zeroconf):
    desc = {
        b"id": b"00:00:01:00:00:02",
        b"md": b"unittest",
        b"s#": b"1",
        b"ci": b"5",
        b"sf": b"0",
    }
    info = ServiceInfo(
        "_hap._tcp.local.",
        "foo2._hap._tcp.local.",
        addresses=[socket.inet_aton("127.0.0.1")],
        port=1234,
        properties=desc,
        weight=0,
        priority=0,
    )
    mock_zeroconf.get_service_info.return_value = info

    result = discover_homekit_devices(max_seconds=0)

    assert result == []


def test_discover_homekit_devices_missing_md(mock_zeroconf):
    desc = {
        b"c#": b"1",
        b"id": b"00:00:01:00:00:02",
        b"s#": b"1",
        b"ci": b"5",
        b"sf": b"0",
    }
    info = ServiceInfo(
        "_hap._tcp.local.",
        "foo2._hap._tcp.local.",
        addresses=[socket.inet_aton("127.0.0.1")],
        port=1234,
        properties=desc,
        weight=0,
        priority=0,
    )
    mock_zeroconf.get_service_info.return_value = info

    result = discover_homekit_devices(max_seconds=0)

    assert result == []


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
