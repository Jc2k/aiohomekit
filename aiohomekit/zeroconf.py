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

"""Helpers for detecing homekit devices via zeroconf."""
from __future__ import annotations

import asyncio
import logging
from typing import Any, Callable

from zeroconf import ServiceBrowser
from zeroconf.asyncio import AsyncServiceBrowser, AsyncServiceInfo, AsyncZeroconf

from aiohomekit.model import Categories
from aiohomekit.model.feature_flags import FeatureFlags

HAP_TYPE_TCP = "_hap._tcp.local."
HAP_TYPE_UDP = "_hap._udp.local."
CLASS_IN = 1
TYPE_PTR = 12

_TIMEOUT_MS = 3000

logger = logging.getLogger(__name__)


def get_from_properties(
    props: dict[str, str],
    key: str,
    default: int | str | None = None,
    case_sensitive: bool = True,
) -> str | None:
    """Convert zeroconf properties to our format.

    This function looks up the key in the given zeroconf service information properties. Those are a dict between bytes.
    The key to lookup is therefore also of type bytes.
    :param props: a dict from bytes to bytes.
    :param key: bytes as key
    :param default: the value to return, if the key was not found. Will be converted to str.
    :param case_sensitive: If this is False, try to lookup keys also when they only match ignoring their case
    :return: the value out of the dict as string (after decoding), the given default if the key was not not found but
             the default was given or None
    """
    if case_sensitive:
        tmp_props = props
        tmp_key = key
    else:
        tmp_props = {k.lower(): props[k] for k in props}
        tmp_key = key.lower()

    if tmp_key in tmp_props:
        return tmp_props[tmp_key]

    if default:
        return str(default)

    return None


def _service_info_is_homekit_device(service_info: AsyncServiceInfo) -> bool:
    props = {key.lower() for key in service_info.properties.keys()}
    print(service_info.parsed_addresses())
    print(props)
    print(
        (
            service_info.parsed_addresses(),
            b"c#" in props,
            b"md" in props,
            b"id" in props,
        )
    )
    return (
        service_info.parsed_addresses()
        and b"c#" in props
        and b"md" in props
        and b"id" in props
    )


def _build_data_from_service_info(service_info) -> dict[str, Any]:
    """Construct data from service_info."""
    # from Bonjour discovery
    data = {
        "name": service_info.name,
        "address": service_info.parsed_addresses()[0],
        "port": service_info.port,
        "type": service_info.type,
    }

    logger.debug(f"candidate data {service_info.properties}")

    data.update(
        parse_discovery_properties(decode_discovery_properties(service_info.properties))
    )

    return data


def decode_discovery_properties(props: dict[bytes, bytes]) -> dict[str, str]:
    """Decode unicode bytes in _hap._tcp Bonjour TXT record keys to python strings.

    :params: a dictionary of key/value TXT records from Bonjour discovery. These are assumed
    to be bytes type.
    :return: A dictionary of key/value TXT records from Bonjour discovery. These are now str.
    """
    return {k.decode("utf-8"): value.decode("utf-8") for k, value in props.items()}


def parse_discovery_properties(props: dict[str, str]) -> dict[str, str | int]:
    """Normalize and parse _hap._tcp Bonjour TXT record keys.

    This is done automatically if you are using the discovery features built in to the library. If you are
    integrating into an existing system it may already do its own Bonjour discovery. In that case you can
    call this function to normalize the properties it has discovered.

    :param props: a dictionary of key/value TXT records from doing Bonjour discovery. These should be
    decoded as strings already. Byte data should be decoded with decode_discovery_properties.
    :return: A dictionary contained the parsed and normalized data.
    """
    data = {}

    # stuff taken from the Bonjour TXT record (see table 5-7 on page 69)
    for prop in ("c#", "id", "md", "s#", "ci", "sf"):
        prop_val = get_from_properties(props, prop, case_sensitive=False)
        if prop_val:
            data[prop] = prop_val

    feature_flags = get_from_properties(props, "ff", case_sensitive=False)
    if feature_flags:
        flags = int(feature_flags)
    else:
        flags = 0
    data["ff"] = flags
    data["flags"] = FeatureFlags(flags)

    protocol_version = get_from_properties(
        props, "pv", case_sensitive=False, default="1.0"
    )
    if protocol_version:
        data["pv"] = protocol_version

    if "ci" in data:
        data["category"] = Categories(int(data["ci"]))

    return data


def async_zeroconf_has_hap_service_browser(
    async_zeroconf_instance: AsyncZeroconf, hap_type: str = HAP_TYPE_TCP
) -> bool:
    """Check to see if the zeroconf instance has an active HAP ServiceBrowser."""
    return any(
        isinstance(listener, (ServiceBrowser, AsyncServiceBrowser))
        and hap_type in listener.types
        for listener in async_zeroconf_instance.zeroconf.listeners
    )


class ZeroconfSubscription:

    """
    This manages attaching to a zeroconf instance to get homekit discovery data.
    """

    def __init__(
        self,
        zeroconf_instance: AsyncZeroconf,
        hap_type: str,
        callback: Callable[..., dict[str, Any]],
    ):
        self._hap_type = hap_type
        self._async_zeroconf_instance = zeroconf_instance
        self._callback = callback

    async def __aenter__(self):
        zc = self._async_zeroconf_instance.zeroconf
        if not zc:
            return self

        # FIXME: This needs to cope with a HA AsyncZeroconf or our own

        for listener in zc.listeners:
            print(listener.types)
            print(dir(listener))
        else:
            self._browser = AsyncServiceBrowser(
                zc,
                [self._hap_type],
                handlers=[self._handle_service],
            )

        infos = [
            AsyncServiceInfo(self._hap_type, record.alias)
            for record in zc.cache.get_all_by_details(
                self._hap_type, TYPE_PTR, CLASS_IN
            )
        ]

        await asyncio.gather(*(self.async_add_service(info) for info in infos))

        return self

    def _handle_service(self, zeroconf, service_type, name, state_change):
        # FIXME: Supposed to hold a reference to this
        info = AsyncServiceInfo(service_type, name)
        asyncio.create_task(self._async_handle_service(info))

    async def _async_handle_service(self, info: AsyncServiceInfo):
        """Add a device that became visible via zeroconf."""
        # AsyncServiceInfo already tries 3x
        await info.async_request(self._async_zeroconf_instance.zeroconf, _TIMEOUT_MS)

        if not _service_info_is_homekit_device(info):
            return

        parsed = _build_data_from_service_info(info)

        self._callback(parsed)

    async def __aexit__(self, *args):
        # FIXME: Detach from zeroconf instance
        pass
