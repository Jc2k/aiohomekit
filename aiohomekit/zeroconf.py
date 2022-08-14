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

import async_timeout
from zeroconf import ServiceListener, ServiceStateChange, Zeroconf
from zeroconf.asyncio import AsyncServiceBrowser, AsyncServiceInfo, AsyncZeroconf

from aiohomekit.characteristic_cache import CharacteristicCacheType
from aiohomekit.controller.abstract import AbstractController, AbstractDiscovery
from aiohomekit.exceptions import AccessoryNotFoundError, TransportNotSupportedError
from aiohomekit.model import Categories
from aiohomekit.model.feature_flags import FeatureFlags
from aiohomekit.model.status_flags import StatusFlags
from aiohomekit.utils import async_create_task

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


def find_brower_for_hap_type(azc: AsyncZeroconf, hap_type: str) -> AsyncServiceBrowser:
    for browser in azc.zeroconf.listeners:
        if not isinstance(browser, AsyncServiceBrowser):
            continue
        if hap_type not in browser.types:
            continue
        return browser

    raise TransportNotSupportedError(f"There is no zeroconf browser for {hap_type}")


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
        self._waiters: dict[str, list[asyncio.Future]] = {}

    async def async_start(self):
        zc = self._async_zeroconf_instance.zeroconf
        if not zc:
            return self

        self._browser = find_brower_for_hap_type(
            self._async_zeroconf_instance, self.hap_type
        )
        self._browser.service_state_changed.register_handler(self._handle_service)

        infos = [
            AsyncServiceInfo(self.hap_type, record.alias)
            for record in zc.cache.get_all_by_details(self.hap_type, TYPE_PTR, CLASS_IN)
        ]

        await asyncio.gather(*(self._async_handle_service(info) for info in infos))

        return self

    def _handle_service(
        self,
        zeroconf: Zeroconf,
        service_type: str,
        name: str,
        state_change: ServiceStateChange,
    ):
        if service_type != self.hap_type:
            return
        info = AsyncServiceInfo(service_type, name)
        async_create_task(self._async_handle_service(info))

    async def async_stop(self):
        self._browser.service_state_changed.unregister_handler(self._handle_service)

    async def async_find(
        self, device_id: str, timeout: float = 10.0
    ) -> ZeroconfDiscovery:
        device_id = device_id.lower()

        if discovery := self.discoveries.get(device_id):
            return discovery

        waiters = self._waiters.setdefault(device_id, [])
        waiter = asyncio.Future()
        waiters.append(waiter)

        try:
            async with async_timeout.timeout(timeout):
                if discovery := await waiter:
                    return discovery
        except asyncio.TimeoutError:
            raise AccessoryNotFoundError(
                f"Accessory with device id {device_id} not found"
            )

    async def async_discover(self) -> AsyncIterable[ZeroconfDiscovery]:
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

        discovery = self.discoveries[description.id] = self._make_discovery(description)

        if pairing := self.pairings.get(description.id):
            pairing._async_description_update(description)

        if waiters := self._waiters.pop(description.id, None):
            for waiter in waiters:
                waiter.set_result(discovery)

    @abstractmethod
    def _make_discovery(self, description: HomeKitService) -> AbstractDiscovery:
        pass
