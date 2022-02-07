from __future__ import annotations

from contextlib import AsyncExitStack
from typing import AsyncIterable

from aiohomekit.controller.abstract import AbstractController
from aiohomekit.controller.coap.discovery import CoAPDiscovery
from aiohomekit.controller.coap.pairing import CoAPPairing
from aiohomekit.exceptions import AccessoryNotFoundError
from aiohomekit.zeroconf import HAP_TYPE_UDP, ZeroconfSubscription


class CoAPController(AbstractController):

    discoveries: dict[str, CoAPDiscovery]
    pairings: dict[str, CoAPPairing]

    def __init__(self, zeroconf_instance):
        super().__init__()

        self._zeroconf_instance = zeroconf_instance
        self._tasks = AsyncExitStack()

    async def async_start(self):
        self._subscription = await self._tasks.enter_async_context(
            ZeroconfSubscription(
                self._zeroconf_instance,
                HAP_TYPE_UDP,
                self._async_add_service,
            )
        )

    async def async_stop(self):
        await self._tasks.aclose()

    async def async_find(self, device_id: str) -> CoAPDiscovery:
        if device_id in self.discoveries:
            return self.discoveries[device_id]

        raise AccessoryNotFoundError(f"Accessory with device id {device_id} not found")

    async def async_discover(self) -> AsyncIterable[CoAPDiscovery]:
        for device in self.discoveries.values():
            yield device

    def _async_add_service(self, discovery):
        """Add a device that became visible via zeroconf."""

        if discovery["id"] in self.discoveries:
            self.discoveries[discovery["id"]]._update_from_discovery(discovery)
            return

        self.discoveries[discovery["id"]] = CoAPDiscovery(self, discovery)
