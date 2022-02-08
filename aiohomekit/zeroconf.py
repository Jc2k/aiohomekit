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

from abc import abstractmethod
import asyncio
import logging
from typing import Any, AsyncIterable

from zeroconf import ServiceBrowser
from zeroconf.asyncio import AsyncServiceBrowser, AsyncServiceInfo, AsyncZeroconf

from aiohomekit.characteristic_cache import CharacteristicCacheType
from aiohomekit.controller.abstract import AbstractController, AbstractDiscovery
from aiohomekit.exceptions import AccessoryNotFoundError
from aiohomekit.model import Categories
from aiohomekit.model.feature_flags import FeatureFlags
from aiohomekit.model.status_flags import StatusFlags

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
) -> str | None:
    """Convert zeroconf properties to our format.

    This function looks up the key in the given zeroconf service information properties. Those are a dict between bytes.
    The key to lookup is therefore also of type bytes.
    :param props: a dict from bytes to bytes.
    :param key: bytes as key
    :param default: the value to return, if the key was not found. Will be converted to str.
    :return: the value out of the dict as string (after decoding), the given default if the key was not not found but
             the default was given or None
    """
    tmp_props = {k.lower(): props[k] for k in props}
    tmp_key = key.lower()

    if tmp_key in tmp_props:
        return tmp_props[tmp_key]

    if default:
        return str(default)

    return None


def _service_info_is_homekit_device(service_info: AsyncServiceInfo) -> bool:
    props = {key.lower() for key in service_info.properties.keys()}
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
    """
    data = {}

    # stuff taken from the Bonjour TXT record (see table 5-7 on page 69)
    for prop in ("c#", "id", "md", "s#", "ci", "sf"):
        prop_val = get_from_properties(props, prop)
        if prop_val:
            data[prop] = prop_val

    data["ff"] = int(get_from_properties(props, "ff", default=0))

    data["pv"] = get_from_properties(props, "pv", default="1.0")

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


class ZeroconfDiscovery(AbstractDiscovery):
    def _update_from_discovery(self, discovery: dict[str, Any]):
        self.name = discovery["id"]
        self.id = discovery["id"]
        self.model = discovery.get("md", "")
        self.config_num = discovery.get("c#", 0)
        self.state_num = discovery.get("s#", 0)
        self.feature_flags = FeatureFlags(discovery["ff"])
        self.status_flags = StatusFlags(int(discovery.get("sf", 0)))
        self.category = Categories(int(discovery.get("ci", 1)))


class ZeroconfController(AbstractController):

    """
    Base class for HAP protocols that rely on Zeroconf discovery.
    """

    hap_type: str

    def __init__(
        self,
        char_cache: CharacteristicCacheType,
        zeroconf_instance: AsyncZeroconf,
    ):
        super().__init__(char_cache)
        self._async_zeroconf_instance = zeroconf_instance

    async def async_start(self):
        zc = self._async_zeroconf_instance.zeroconf
        if not zc:
            return self

        # FIXME: This needs to cope with a HA AsyncZeroconf or our own

        for listener in zc.listeners:
            pass
        else:
            self._browser = AsyncServiceBrowser(
                zc,
                [self.hap_type],
                handlers=[self._handle_service],
            )

        infos = [
            AsyncServiceInfo(self.hap_type, record.alias)
            for record in zc.cache.get_all_by_details(self.hap_type, TYPE_PTR, CLASS_IN)
        ]

        await asyncio.gather(*(self._async_handle_service(info) for info in infos))

    async def async_stop(self):
        # FIXME: Detach from zeroconf instance
        pass

    async def async_find(self, device_id: str) -> AbstractDiscovery:
        if device_id in self.discoveries:
            return self.discoveries[device_id]

        raise AccessoryNotFoundError(f"Accessory with device id {device_id} not found")

    async def async_discover(self) -> AsyncIterable[AbstractDiscovery]:
        for device in self.discoveries.values():
            yield device

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

        discovery = _build_data_from_service_info(info)

        if discovery["id"] in self.discoveries:
            self.discoveries[discovery["id"]]._update_from_discovery(discovery)
            return

        self.discoveries[discovery["id"]] = self._make_discovery(discovery)

    @abstractmethod
    def _make_discovery(self, discovery) -> AbstractDiscovery:
        pass
