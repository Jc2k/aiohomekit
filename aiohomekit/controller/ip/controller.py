from __future__ import annotations

import asyncio
from typing import TYPE_CHECKING

from zeroconf.asyncio import AsyncServiceBrowser, AsyncServiceInfo

from aiohomekit.controller.ip.discovery import IpDiscovery

if TYPE_CHECKING:
    from aiohomekit.controller import Controller


class IpController:

    devices: dict[str, IpDiscovery]

    def __init__(self, controller: Controller):
        self._controller = controller
        self.devices = {}

    async def __aenter__(self):
        zc = self._controller._async_zeroconf_instance
        if not zc:
            return self

        for listener in zc.zeroconf.listeners:
            print(listener.types)
            print(dir(listener))
        else:
            self._browser = AsyncServiceBrowser(
                zc.zeroconf,
                ["_hap._tcp.local."],
                handlers=[self.add_service],
            )

        return self

    def add_service(self, zeroconf, service_type, name, state_change):
        # self.devices[device_id] = IpDiscovery(self, device)
        # FIXME: Supposed to hold a reference to this
        asyncio.create_task(self.async_add_service(zeroconf, service_type, name))

    async def async_add_service(self, zeroconf, service_type, name):
        """Add a device that became visible via zeroconf."""
        # AsyncServiceInfo already tries 3x
        info = AsyncServiceInfo(service_type, name)
        await info.async_request(zeroconf, 3000)

        print(info.properties)

        from aiohomekit.zeroconf import _build_data_from_service_info

        parsed = _build_data_from_service_info(info)

        if "c#" not in parsed:
            return

        self.devices[parsed["id"]] = IpDiscovery(self, parsed)

    async def __aexit__(self, *args):
        pass
