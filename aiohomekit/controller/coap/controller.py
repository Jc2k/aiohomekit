from __future__ import annotations

from typing import Any

from aiohomekit.controller.abstract import TransportType
from aiohomekit.controller.coap.discovery import CoAPDiscovery
from aiohomekit.controller.coap.pairing import CoAPPairing
from aiohomekit.zeroconf import HAP_TYPE_UDP, ZeroconfController


class CoAPController(ZeroconfController):
    hap_type = HAP_TYPE_UDP
    discoveries: dict[str, CoAPDiscovery]
    pairings: dict[str, CoAPPairing]
    aliases: dict[str, CoAPPairing]
    transport_type = TransportType.COAP

    def _make_discovery(self, discovery) -> CoAPDiscovery:
        return CoAPDiscovery(self, discovery)

    def load_pairing(
        self, alias: str, pairing_data: dict[str, Any]
    ) -> CoAPPairing | None:
        if pairing_data["Connection"] != "CoAP":
            return None

        if not (hkid := pairing_data.get("AccessoryPairingID")):
            return None

        pairing = self.pairings[hkid.lower()] = CoAPPairing(self, pairing_data)

        if discovery := self.discoveries.get(hkid.lower()):
            pairing._async_description_update(discovery.description)

        self.aliases[alias] = pairing

        return pairing
