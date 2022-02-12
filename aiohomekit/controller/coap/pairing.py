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

import asyncio
import logging

from aiohomekit.controller.abstract import AbstractPairing
from aiohomekit.uuid import normalize_uuid

from .connection import CoAPHomeKitConnection

logger = logging.getLogger(__name__)


class CoAPPairing(AbstractPairing):
    def __init__(self, controller, pairing_data):
        super().__init__(controller)

        self.id = pairing_data["AccessoryPairingID"]

        self.connection = CoAPHomeKitConnection(
            self, pairing_data["AccessoryIP"], pairing_data["AccessoryPort"]
        )
        self.connection_lock = asyncio.Lock()
        self.pairing_data = pairing_data

    @property
    def is_connected(self):
        return self.connection.is_connected

    async def _ensure_connected(self):
        async with self.connection_lock:
            if self.connection.is_connected:
                return

            await self.connection.connect(self.pairing_data)

            # in case this was a reconnect, re-subscribe
            if len(self.subscriptions):
                logger.debug(
                    "(Re-)subscribing to %d characteristics: %r"
                    % (len(self.subscriptions), self.subscriptions)
                )
                await self.connection.subscribe_to(list(self.subscriptions))

        return

    async def close(self):
        if self.connection.is_connected:
            await self.unsubscribe(list(self.subscriptions))
        return

    def event_received(self, event):
        self._callback_listeners(event)

    def _callback_listeners(self, event):
        for listener in self.listeners:
            try:
                logger.debug(f"callback ev:{event!r}")
                listener(event)
            except Exception:
                logger.exception("Unhandled error when processing event")

    async def identify(self):
        await self._ensure_connected()
        return await self.connection.do_identify()

    async def list_accessories_and_characteristics(self):
        await self._ensure_connected()

        accessories = await self.connection.get_accessory_info()

        for accessory in accessories:
            for service in accessory["services"]:
                service["type"] = normalize_uuid(service["type"])

                for characteristic in service["characteristics"]:
                    characteristic["type"] = normalize_uuid(characteristic["type"])

        return accessories

    async def get_characteristics(
        self,
        characteristics,
    ):
        await self._ensure_connected()
        return await self.connection.read_characteristics(characteristics)

    async def put_characteristics(self, characteristics):
        await self._ensure_connected()
        return await self.connection.write_characteristics(characteristics)

    async def subscribe(self, characteristics):
        await self._ensure_connected()
        new_subs = await super().subscribe(set(characteristics))
        if len(new_subs) == 0:
            logger.debug("Nothing new to subscribe to, ignoring")
            return
        return await self.connection.subscribe_to(list(new_subs))

    async def unsubscribe(self, characteristics):
        await self._ensure_connected()
        await super().unsubscribe(set(characteristics))
        return await self.connection.unsubscribe_from(characteristics)

    async def list_pairings(self):
        await self._ensure_connected()
        pairing_tuples = await self.connection.list_pairings()
        pairings = list(
            map(
                lambda x: dict(
                    (
                        ("pairingId", x[0].decode()),
                        ("publicKey", x[1].hex()),
                        ("permissions", x[2]),
                        ("controllerType", x[2] & 0x01 and "admin" or "regular"),
                    )
                ),
                pairing_tuples,
            )
        )
        return pairings

    async def remove_pairing(self, pairingId):
        await self._ensure_connected()
        return await self.connection.remove_pairing(pairingId)
