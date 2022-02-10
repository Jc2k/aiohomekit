from __future__ import annotations

from aiohomekit.controller.coap.discovery import CoAPDiscovery
from aiohomekit.controller.coap.pairing import CoAPPairing
from aiohomekit.zeroconf import HAP_TYPE_UDP, ZeroconfController


class CoAPController(ZeroconfController):

    hap_type = HAP_TYPE_UDP
    discoveries: dict[str, CoAPDiscovery]
    pairings: dict[str, CoAPPairing]

    def _make_discovery(self, discovery) -> CoAPDiscovery:
        return CoAPDiscovery(self, discovery)
