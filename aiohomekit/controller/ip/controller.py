from __future__ import annotations

from contextlib import AsyncExitStack
from typing import AsyncIterable

from aiohomekit.controller.abstract import AbstractController
from aiohomekit.controller.ip.discovery import IpDiscovery
from aiohomekit.controller.ip.pairing import IpPairing
from aiohomekit.exceptions import AccessoryNotFoundError
from aiohomekit.zeroconf import HAP_TYPE_TCP, ZeroconfSubscription


class IpController(AbstractController):

    discoveries: dict[str, IpDiscovery]
    pairings: dict[str, IpPairing]

    def __init__(self, zeroconf_instance):
        super().__init__()

        self._tasks = AsyncExitStack()
        self._zeroconf_instance = zeroconf_instance

    async def async_start(self):
        self._subscription = await self._tasks.enter_async_context(
            ZeroconfSubscription(
                self._zeroconf_instance,
                HAP_TYPE_TCP,
                self._async_add_service,
            )
        )

    async def async_stop(self):
        await self._tasks.aclose()

    async def async_find(self, device_id: str) -> IpDiscovery:
        if device_id in self.discoveries:
            return self.discoveries[device_id]

        raise AccessoryNotFoundError(f"Accessory with device id {device_id} not found")

    async def async_discover(self) -> AsyncIterable[IpDiscovery]:
        for device in self.discoveries.values():
            yield device

    def _async_add_service(self, discovery):
        """Add a device that became visible via zeroconf."""

        if discovery["id"] in self.discoveries:
            self.discoveries[discovery["id"]]._update_from_discovery(discovery)
            return

        self.discoveries[discovery["id"]] = IpDiscovery(self, discovery)
