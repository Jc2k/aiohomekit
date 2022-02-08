from __future__ import annotations

from aiohomekit.controller.ip.discovery import IpDiscovery
from aiohomekit.controller.ip.pairing import IpPairing
from aiohomekit.zeroconf import HAP_TYPE_TCP, ZeroconfController


class IpController(ZeroconfController):

    hap_type = HAP_TYPE_TCP
    discoveries: dict[str, IpDiscovery]
    pairings: dict[str, IpPairing]

    def _make_discovery(self, discovery) -> IpDiscovery:
        return IpDiscovery(self, discovery)
