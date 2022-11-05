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

import pytest
from zeroconf.asyncio import AsyncServiceInfo

from aiohomekit.model.categories import Categories
from aiohomekit.model.feature_flags import FeatureFlags
from aiohomekit.zeroconf import HomeKitService


def test_simple():
    desc = {
        b"c#": b"1",
        b"id": b"00:00:01:00:00:02",
        b"md": b"unittest",
        b"s#": b"11",
        b"ci": b"5",
        b"sf": b"0",
        b"ff": b"1",
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
    svc = HomeKitService.from_service_info(info)

    assert svc.name == "foo2"
    assert svc.type == "_hap._tcp.local."
    assert svc.id == "00:00:01:00:00:02"
    assert svc.model == "unittest"
    assert svc.config_num == 1
    assert svc.state_num == 11
    assert svc.status_flags == 0
    assert svc.feature_flags == FeatureFlags.SUPPORTS_APPLE_AUTHENTICATION_COPROCESSOR
    assert svc.category == Categories.LIGHTBULB
    assert svc.address == "127.0.0.1"
    assert svc.addresses == ["127.0.0.1"]
    assert svc.port == 1234


def test_udp():
    desc = {
        b"c#": b"1",
        b"id": b"00:00:01:00:00:02",
        b"md": b"unittest",
        b"s#": b"11",
        b"ci": b"5",
        b"sf": b"0",
        b"ff": b"1",
    }
    info = AsyncServiceInfo(
        "_hap._udp.local.",
        "foo2._hap._udp.local.",
        addresses=[socket.inet_aton("127.0.0.1")],
        port=1234,
        properties=desc,
        weight=0,
        priority=0,
    )
    svc = HomeKitService.from_service_info(info)

    assert svc.name == "foo2"
    assert svc.type == "_hap._udp.local."


def test_upper_case_keys():
    desc = {
        b"C#": b"1",
        b"ID": b"00:00:01:00:00:02",
        b"MD": b"unittest",
        b"S#": b"11",
        b"CI": b"5",
        b"SF": b"0",
        b"FF": b"1",
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
    svc = HomeKitService.from_service_info(info)

    assert svc.name == "foo2"
    assert svc.type == "_hap._tcp.local."
    assert svc.id == "00:00:01:00:00:02"
    assert svc.model == "unittest"
    assert svc.config_num == 1
    assert svc.state_num == 11
    assert svc.status_flags == 0
    assert svc.feature_flags == FeatureFlags.SUPPORTS_APPLE_AUTHENTICATION_COPROCESSOR
    assert svc.category == Categories.LIGHTBULB
    assert svc.address == "127.0.0.1"
    assert svc.addresses == ["127.0.0.1"]
    assert svc.port == 1234


def test_missing_cn():
    desc = {
        b"id": b"00:00:01:00:00:02",
        b"md": b"unittest",
        b"s#": b"11",
        b"ci": b"5",
        b"sf": b"0",
        b"ff": b"1",
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
    svc = HomeKitService.from_service_info(info)

    assert svc.config_num == 0


def test_missing_sn():
    desc = {
        b"c#": b"11",
        b"id": b"00:00:01:00:00:02",
        b"md": b"unittest",
        b"ci": b"5",
        b"sf": b"0",
        b"ff": b"1",
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
    svc = HomeKitService.from_service_info(info)

    assert svc.state_num == 0


def test_missing_sf():
    desc = {
        b"c#": b"11",
        b"id": b"00:00:01:00:00:02",
        b"md": b"unittest",
        b"ci": b"5",
        b"s#": b"15",
        b"ff": b"1",
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
    svc = HomeKitService.from_service_info(info)

    assert svc.status_flags == 0


def test_missing_ff():
    desc = {
        b"c#": b"11",
        b"id": b"00:00:01:00:00:02",
        b"md": b"unittest",
        b"ci": b"5",
        b"s#": b"15",
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
    svc = HomeKitService.from_service_info(info)

    assert svc.feature_flags == 0


def test_missing_md():
    desc = {
        b"c#": b"11",
        b"id": b"00:00:01:00:00:02",
        b"ci": b"5",
        b"s#": b"15",
        b"sf": b"0",
        b"ff": b"44",
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
    svc = HomeKitService.from_service_info(info)

    assert svc.model == ""


def test_missing_ci():
    desc = {
        b"c#": b"11",
        b"id": b"00:00:01:00:00:02",
        b"md": b"unittest",
        b"s#": b"15",
        b"sf": b"0",
        b"ff": b"44",
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
    svc = HomeKitService.from_service_info(info)

    assert svc.category == Categories.OTHER


def test_missing_id():
    desc = {
        b"c#": b"11",
        b"md": b"unittest",
        b"s#": b"15",
        b"sf": b"0",
        b"ff": b"44",
        b"ci": b"0",
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

    with pytest.raises(ValueError):
        HomeKitService.from_service_info(info)


def test_ignore_link_local():
    desc = {
        b"c#": b"1",
        b"id": b"00:00:01:00:00:02",
        b"md": b"unittest",
        b"s#": b"11",
        b"ci": b"5",
        b"sf": b"0",
        b"ff": b"1",
    }
    info = AsyncServiceInfo(
        "_hap._tcp.local.",
        "foo2._hap._tcp.local.",
        addresses=[socket.inet_aton("169.254.121.37"), socket.inet_aton("127.0.0.1")],
        port=1234,
        properties=desc,
        weight=0,
        priority=0,
    )
    svc = HomeKitService.from_service_info(info)

    assert svc.name == "foo2"
    assert svc.type == "_hap._tcp.local."
    assert svc.id == "00:00:01:00:00:02"
    assert svc.model == "unittest"
    assert svc.config_num == 1
    assert svc.state_num == 11
    assert svc.status_flags == 0
    assert svc.feature_flags == FeatureFlags.SUPPORTS_APPLE_AUTHENTICATION_COPROCESSOR
    assert svc.category == Categories.LIGHTBULB
    assert svc.address == "127.0.0.1"
    assert svc.addresses == ["169.254.121.37", "127.0.0.1"]
    assert svc.port == 1234


def test_ignore_link_local_ipv6():
    desc = {
        b"c#": b"1",
        b"id": b"00:00:01:00:00:02",
        b"md": b"unittest",
        b"s#": b"11",
        b"ci": b"5",
        b"sf": b"0",
        b"ff": b"1",
    }
    info = AsyncServiceInfo(
        "_hap._tcp.local.",
        "foo2._hap._tcp.local.",
        addresses=[
            socket.inet_aton("169.254.121.37"),
            socket.inet_pton(socket.AF_INET6, "2a00:1450:4009:820::200e"),
        ],
        port=1234,
        properties=desc,
        weight=0,
        priority=0,
    )
    svc = HomeKitService.from_service_info(info)

    assert svc.name == "foo2"
    assert svc.type == "_hap._tcp.local."
    assert svc.id == "00:00:01:00:00:02"
    assert svc.model == "unittest"
    assert svc.config_num == 1
    assert svc.state_num == 11
    assert svc.status_flags == 0
    assert svc.feature_flags == FeatureFlags.SUPPORTS_APPLE_AUTHENTICATION_COPROCESSOR
    assert svc.category == Categories.LIGHTBULB
    assert svc.address == "2a00:1450:4009:820::200e"
    assert svc.addresses == ["169.254.121.37", "2a00:1450:4009:820::200e"]
    assert svc.port == 1234


def test_prefer_ipv4():
    desc = {
        b"c#": b"1",
        b"id": b"00:00:01:00:00:02",
        b"md": b"unittest",
        b"s#": b"11",
        b"ci": b"5",
        b"sf": b"0",
        b"ff": b"1",
    }
    info = AsyncServiceInfo(
        "_hap._tcp.local.",
        "foo2._hap._tcp.local.",
        addresses=[
            socket.inet_pton(socket.AF_INET6, "2a00:1450:4009:820::200e"),
            socket.inet_aton("127.0.0.1"),
        ],
        port=1234,
        properties=desc,
        weight=0,
        priority=0,
    )
    svc = HomeKitService.from_service_info(info)

    assert svc.name == "foo2"
    assert svc.type == "_hap._tcp.local."
    assert svc.id == "00:00:01:00:00:02"
    assert svc.model == "unittest"
    assert svc.config_num == 1
    assert svc.state_num == 11
    assert svc.status_flags == 0
    assert svc.feature_flags == FeatureFlags.SUPPORTS_APPLE_AUTHENTICATION_COPROCESSOR
    assert svc.category == Categories.LIGHTBULB
    assert svc.address == "127.0.0.1"
    assert svc.addresses == ["127.0.0.1", "2a00:1450:4009:820::200e"]
    assert svc.port == 1234


def test_ignore_unspecified():
    desc = {
        b"c#": b"1",
        b"id": b"00:00:01:00:00:02",
        b"md": b"unittest",
        b"s#": b"11",
        b"ci": b"5",
        b"sf": b"0",
        b"ff": b"1",
    }
    info = AsyncServiceInfo(
        "_hap._tcp.local.",
        "foo2._hap._tcp.local.",
        addresses=[socket.inet_aton("0.0.0.0"), socket.inet_aton("127.0.0.1")],
        port=1234,
        properties=desc,
        weight=0,
        priority=0,
    )
    svc = HomeKitService.from_service_info(info)

    assert svc.name == "foo2"
    assert svc.type == "_hap._tcp.local."
    assert svc.id == "00:00:01:00:00:02"
    assert svc.model == "unittest"
    assert svc.config_num == 1
    assert svc.state_num == 11
    assert svc.status_flags == 0
    assert svc.feature_flags == FeatureFlags.SUPPORTS_APPLE_AUTHENTICATION_COPROCESSOR
    assert svc.category == Categories.LIGHTBULB
    assert svc.address == "127.0.0.1"
    assert svc.addresses == ["0.0.0.0", "127.0.0.1"]
    assert svc.port == 1234


def test_ignore_unspecified_ipv6():
    desc = {
        b"c#": b"1",
        b"id": b"00:00:01:00:00:02",
        b"md": b"unittest",
        b"s#": b"11",
        b"ci": b"5",
        b"sf": b"0",
        b"ff": b"1",
    }
    info = AsyncServiceInfo(
        "_hap._tcp.local.",
        "foo2._hap._tcp.local.",
        addresses=[
            socket.inet_aton("0.0.0.0"),
            socket.inet_pton(socket.AF_INET6, "2a00:1450:4009:820::200e"),
        ],
        port=1234,
        properties=desc,
        weight=0,
        priority=0,
    )
    svc = HomeKitService.from_service_info(info)

    assert svc.name == "foo2"
    assert svc.type == "_hap._tcp.local."
    assert svc.id == "00:00:01:00:00:02"
    assert svc.model == "unittest"
    assert svc.config_num == 1
    assert svc.state_num == 11
    assert svc.status_flags == 0
    assert svc.feature_flags == FeatureFlags.SUPPORTS_APPLE_AUTHENTICATION_COPROCESSOR
    assert svc.category == Categories.LIGHTBULB
    assert svc.address == "2a00:1450:4009:820::200e"
    assert svc.addresses == ["0.0.0.0", "2a00:1450:4009:820::200e"]
    assert svc.port == 1234
