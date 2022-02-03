#
# Copyright 2022 aiohomekit team
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

import logging
from typing import Any

from ..pairing import AbstractPairing

logger = logging.getLogger(__name__)


class BlePairing(AbstractPairing):
    """
    This represents a paired HomeKit IP accessory.
    """

    def __init__(self, controller, pairing_data):
        super().__init__(controller)
        self.pairing_data = pairing_data

    async def close(self):
        pass

    async def list_accessories_and_characteristics(self):
        pass

    async def list_pairings(self):
        pass

    async def get_characteristics(
        self,
        characteristics: list[tuple[int, int]],
        include_meta=False,
        include_perms=False,
        include_type=False,
        include_events=False,
    ) -> dict[tuple[int, int], Any]:
        return {}

    async def put_characteristics(self, characteristics: list[tuple[int, int, Any]]):
        pass

    async def subscribe(self, characteristics):
        pass

    async def unsubscribe(self, characteristics):
        pass

    async def identify(self):
        pass

    async def add_pairing(
        self, additional_controller_pairing_identifier, ios_device_ltpk, permissions
    ):
        pass

    async def remove_pairing(self, pairingId: str):
        pass

    async def image(self, accessory: int, width: int, height: int) -> None:
        """Bluetooth devices don't return images."""
        return None
