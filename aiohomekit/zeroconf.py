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
from dataclasses import dataclass
import logging
from typing import AsyncIterable

from zeroconf import ServiceListener, Zeroconf
from zeroconf.asyncio import AsyncServiceInfo, AsyncZeroconf

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


@dataclass
class HomeKitService:

    name: str
    id: str
    model: str
    feature_flags: FeatureFlags
    status_flags: StatusFlags
    config_num: int
    state_num: int
    category: Categories
    protocol_version: str

    type: str

    address: str
    addresses: list[str]
    port: int

    @classmethod
    def from_service_info(cls, service: AsyncServiceInfo) -> HomeKitService:
        if not (addresses := service.parsed_addresses()):
            raise ValueError("Invalid HomeKit Zeroconf record: Missing address")

        props: dict[str, str] = {
            k.decode("utf-8").lower(): v.decode("utf-8")
            for (k, v) in service.properties.items()
        }

        if "id" not in props:
            raise ValueError("Invalid HomeKit Zeroconf record: Missing device ID")

        return cls(
            name=service.name.removesuffix(f".{service.type}"),
            id=props["id"].lower(),
            model=props.get("md", ""),
            config_num=int(props.get("c#", 0)),
            state_num=int(props.get("s#", 0)),
            feature_flags=FeatureFlags(int(props.get("ff", 0))),
            status_flags=StatusFlags(int(props.get("sf", 0))),
            category=Categories(int(props.get("ci", 1))),
            protocol_version=props.get("pv", "1.0"),
            type=service.type,
            address=addresses[0],
            addresses=addresses,
            port=service.port,
        )


class ZeroconfServiceListener(ServiceListener):
    """An empty service listener."""

    def add_service(self, zc: Zeroconf, type_: str, name: str) -> None:
        pass

    def remove_service(self, zc: Zeroconf, type_: str, name: str) -> None:
        pass

    def update_service(self, zc: Zeroconf, type_: str, name: str) -> None:
        pass


class ZeroconfDiscovery(AbstractDiscovery):

    description: HomeKitService

    def __init__(self, description: HomeKitService):
        self.description = description

    def _update_from_discovery(self, description: HomeKitService):
        self.description = description


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

        # FIXME: Ideally we want to attach to the zeroconf instance here and monitor for
        # 1. Hostname/port changes
        # 2. C# getting incremented
        # zc.async_add_listener(self, None)

    async def async_stop(self):
        # FIXME: Detach from zeroconf instance
        pass

    async def async_find(self, device_id: str) -> AbstractDiscovery:
        device_id = device_id.lower()

        async for device in self.async_discover():
            if device.description.id == device_id:
                return device

        raise AccessoryNotFoundError(f"Accessory with device id {device_id} not found")

    async def async_discover(self) -> AsyncIterable[AbstractDiscovery]:
        zc = self._async_zeroconf_instance.zeroconf
        infos = [
            AsyncServiceInfo(self.hap_type, record.alias)
            for record in zc.cache.get_all_by_details(self.hap_type, TYPE_PTR, CLASS_IN)
        ]

        await asyncio.gather(*(self._async_handle_service(info) for info in infos))

        for device in self.discoveries.values():
            yield device

    async def _async_handle_service(self, info: AsyncServiceInfo):
        """Add a device that became visible via zeroconf."""
        # AsyncServiceInfo already tries 3x
        await info.async_request(self._async_zeroconf_instance.zeroconf, _TIMEOUT_MS)

        try:
            description = HomeKitService.from_service_info(info)
        except ValueError:
            logger.debug("Not a valid homekit device")
            return

        if description.id in self.discoveries:
            self.discoveries[description.id]._update_from_discovery(description)
            return

        self.discoveries[description.id] = self._make_discovery(description)

    @abstractmethod
    def _make_discovery(self, description: HomeKitService) -> AbstractDiscovery:
        pass
