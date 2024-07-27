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
from collections.abc import AsyncIterable
from dataclasses import dataclass
import logging

from zeroconf import (
    BadTypeInNameException,
    DNSPointer,
    IPVersion,
    ServiceListener,
    ServiceStateChange,
    Zeroconf,
    current_time_millis,
)
from zeroconf.asyncio import AsyncServiceBrowser, AsyncServiceInfo, AsyncZeroconf

from aiohomekit.characteristic_cache import CharacteristicCacheType
from aiohomekit.controller.abstract import (
    AbstractController,
    AbstractDiscovery,
    AbstractPairing,
)
from aiohomekit.exceptions import AccessoryNotFoundError, TransportNotSupportedError
from aiohomekit.model import Categories
from aiohomekit.model.feature_flags import FeatureFlags
from aiohomekit.model.status_flags import StatusFlags

from .utils import async_create_task

HAP_TYPE_TCP = "_hap._tcp.local."
HAP_TYPE_UDP = "_hap._udp.local."
CLASS_IN = 1
TYPE_PTR = 12

_TIMEOUT_MS = 3000

logger = logging.getLogger(__name__)


@dataclass(slots=True)
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
        if not (addresses := service.ip_addresses_by_version(IPVersion.All)):
            raise ValueError("Invalid HomeKit Zeroconf record: Missing address")

        address: str | None = None
        #
        # Zeroconf addresses are guaranteed to be returned in LIFO (last in, first out)
        # order with IPv4 addresses first and IPv6 addresses second.
        #
        # This means the first address will always be the most recently added
        # address of the given IP version.
        #
        valid_addresses = [
            str(ip_addr)
            for ip_addr in addresses
            if not ip_addr.is_link_local and not ip_addr.is_unspecified
        ]
        if not valid_addresses:
            raise ValueError(
                "Invalid HomeKit Zeroconf record: Missing non-link-local or unspecified address"
            )
        address = valid_addresses[0]
        props = {
            k.lower(): v for k, v in service.decoded_properties.items() if v is not None
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
            address=address,
            addresses=valid_addresses,
            port=service.port,
        )


class ZeroconfServiceListener(ServiceListener):
    """An empty service listener."""

    def add_service(self, zc: Zeroconf, type_: str, name: str) -> None:
        """A service has been added."""

    def remove_service(self, zc: Zeroconf, type_: str, name: str) -> None:
        """A service has been removed."""

    def update_service(self, zc: Zeroconf, type_: str, name: str) -> None:
        """A service has been updated."""


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


class ZeroconfPairing(AbstractPairing):
    description: HomeKitService

    def _async_endpoint_changed(self) -> None:
        """The IP and/or port of the accessory has changed."""
        pass

    def _async_description_update(self, description: HomeKitService | None) -> None:
        old_description = self.description

        super()._async_description_update(description)

        if not description:
            return

        endpoint_changed = False
        if not old_description:
            logger.debug("%s: Device rediscovered", self.id)
            endpoint_changed = True
        elif old_description.address != description.address:
            logger.debug(
                "%s: Device IP changed from %s to %s",
                self.id,
                old_description.address,
                description.address,
            )
            endpoint_changed = True
        elif old_description.port != description.port:
            logger.debug(
                "%s: Device port changed from %s to %s",
                self.id,
                old_description.port,
                description.port,
            )
            endpoint_changed = True

        if endpoint_changed:
            self._async_endpoint_changed()


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
        self._resolve_later: dict[str, asyncio.TimerHandle] = {}
        self._loop = asyncio.get_running_loop()
        self._running = True

    async def async_start(self):
        zc = self._async_zeroconf_instance.zeroconf
        if not zc:
            return self

        self._browser = find_brower_for_hap_type(
            self._async_zeroconf_instance, self.hap_type
        )
        self._browser.service_state_changed.register_handler(self._handle_service)
        await self._async_update_from_cache(zc)

        return self

    async def _async_update_from_cache(self, zc: Zeroconf) -> None:
        """Load the records from the cache."""
        tasks: list[asyncio.Task] = []
        now = current_time_millis()
        for record in self._async_get_ptr_records(zc):
            try:
                info = AsyncServiceInfo(self.hap_type, record.alias)
            except BadTypeInNameException as ex:
                logger.debug(
                    "Ignoring record with bad type in name: %s: %s", record.alias, ex
                )
                continue
            if info.load_from_cache(zc, now):
                self._async_handle_loaded_service_info(info)
            else:
                tasks.append(self._async_handle_service(info))

        if tasks:
            await asyncio.gather(*tasks)

    def _async_get_ptr_records(self, zc: Zeroconf) -> list[DNSPointer]:
        """Return all PTR records for the HAP type."""
        return zc.cache.async_all_by_details(self.hap_type, TYPE_PTR, CLASS_IN)

    def _handle_service(
        self,
        zeroconf: Zeroconf,
        service_type: str,
        name: str,
        state_change: ServiceStateChange,
    ) -> None:
        if service_type != self.hap_type:
            return

        if state_change == ServiceStateChange.Removed:
            if cancel := self._resolve_later.pop(name, None):
                cancel.cancel()
            return

        if name in self._resolve_later:
            # We already have a timer to resolve this service, so ignore this
            # callback.
            return

        try:
            info = AsyncServiceInfo(service_type, name)
        except BadTypeInNameException as ex:
            logger.debug("Ignoring record with bad type in name: %s: %s", name, ex)
            return

        self._resolve_later[name] = self._loop.call_at(
            self._loop.time() + 0.5, self._async_resolve_later, name, info
        )

    def _async_resolve_later(self, name: str, info: AsyncServiceInfo) -> None:
        """Resolve a host later."""
        # As soon as we get a callback, we can remove the _resolve_later
        # so the next time we get a callback, we can resolve the service
        # again if needed which ensures the TTL is respected.
        self._resolve_later.pop(name, None)

        if not self._running:
            return

        if info.load_from_cache(self._async_zeroconf_instance.zeroconf):
            self._async_handle_loaded_service_info(info)
        else:
            async_create_task(self._async_handle_service(info))

    async def async_stop(self):
        """Stop the controller."""
        self._running = False
        self._browser.service_state_changed.unregister_handler(self._handle_service)
        while self._resolve_later:
            _, cancel = self._resolve_later.popitem()
            cancel.cancel()

    async def async_find(
        self, device_id: str, timeout: float = 10.0
    ) -> ZeroconfDiscovery:
        device_id = device_id.lower()

        if discovery := self.discoveries.get(device_id):
            return discovery

        waiters = self._waiters.setdefault(device_id, [])
        waiter = self._loop.create_future()
        waiters.append(waiter)
        cancel_timeout = self._loop.call_later(timeout, self._async_on_timeout, waiter)

        try:
            if discovery := await waiter:
                return discovery
        except asyncio.TimeoutError:
            raise AccessoryNotFoundError(
                f"Accessory with device id {device_id} not found"
            )
        finally:
            cancel_timeout.cancel()

    async def async_reachable(self, device_id: str, timeout: float = 10.0) -> bool:
        """Check if a device is reachable.

        This method will return True if the device is reachable, False if it is not.

        Typically A/AAAA records have a TTL of 120 seconds which means we may
        see the device as reachable for up to 120 seconds after it has been
        removed from the network if it does not send a goodbye packet.
        """
        try:
            discovery = await self.async_find(device_id, timeout)
        except AccessoryNotFoundError:
            return False
        alias = f"{discovery.description.name}.{self.hap_type}"
        info = AsyncServiceInfo(self.hap_type, alias)
        zc = self._async_zeroconf_instance.zeroconf
        return info.load_from_cache(zc) or await info.async_request(zc, _TIMEOUT_MS)

    def _async_on_timeout(self, future: asyncio.Future) -> None:
        if not future.done():
            future.set_exception(asyncio.TimeoutError())

    async def async_discover(self) -> AsyncIterable[ZeroconfDiscovery]:
        for device in self.discoveries.values():
            yield device

    async def _async_handle_service(self, info: AsyncServiceInfo):
        """Add a device that became visible via zeroconf."""
        # AsyncServiceInfo already tries 3x
        await info.async_request(self._async_zeroconf_instance.zeroconf, _TIMEOUT_MS)
        self._async_handle_loaded_service_info(info)

    def _async_handle_loaded_service_info(self, info: AsyncServiceInfo) -> None:
        """Handle a service info that was discovered via zeroconf."""
        try:
            description = HomeKitService.from_service_info(info)
        except ValueError as e:
            logger.debug("%s: Not a valid homekit device: %s", info.name, e)
            return

        if discovery := self.discoveries.get(description.id):
            discovery._update_from_discovery(description)
        else:
            discovery = self.discoveries[description.id] = self._make_discovery(
                description
            )

        discovery = self.discoveries[description.id] = self._make_discovery(description)

        if pairing := self.pairings.get(description.id):
            logger.debug(
                "%s: Notifying pairing of description update: %s",
                description.id,
                description,
            )
            pairing._async_description_update(description)

        if waiters := self._waiters.pop(description.id, None):
            for waiter in waiters:
                if not waiter.cancelled() and not waiter.done():
                    waiter.set_result(discovery)

    @abstractmethod
    def _make_discovery(self, description: HomeKitService) -> AbstractDiscovery:
        pass
