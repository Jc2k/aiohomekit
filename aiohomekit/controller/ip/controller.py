from __future__ import annotations

from contextlib import AsyncExitStack
from typing import TYPE_CHECKING

from aiohomekit.controller.ip.discovery import IpDiscovery
from aiohomekit.zeroconf import HAP_TYPE_TCP, ZeroconfSubscription

if TYPE_CHECKING:
    from aiohomekit.controller import Controller


class IpController:

    devices: dict[str, IpDiscovery]

    def __init__(self, controller: Controller):
        self._controller = controller
        self._tasks = AsyncExitStack()

        self.devices = {}

    async def __aenter__(self):
        self._subscription = await self._tasks.enter_async_context(
            ZeroconfSubscription(
                self._controller._async_zeroconf_instance,
                HAP_TYPE_TCP,
                self._async_add_service,
            )
        )

        return self

    async def __aexit__(self, *args):
        await self._tasks.aclose()

    def _async_add_service(self, discovery):
        """Add a device that became visible via zeroconf."""

        print(discovery)

        if discovery["id"] in self.devices:
            self.devices[discovery["id"]]._update_from_discovery(discovery)
            return

        self.devices[discovery["id"]] = IpDiscovery(self, discovery)
