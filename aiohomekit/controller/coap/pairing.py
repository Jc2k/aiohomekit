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
from __future__ import annotations

import asyncio
from collections.abc import Iterable
from datetime import timedelta
import logging
from typing import Any

from aiohomekit.controller.abstract import AbstractController, AbstractPairingData
from aiohomekit.exceptions import AccessoryDisconnectedError
from aiohomekit.model import Accessories, AccessoriesState, Transport
from aiohomekit.model.characteristics import CharacteristicPermissions
from aiohomekit.protocol.statuscodes import HapStatusCode
from aiohomekit.utils import async_create_task
from aiohomekit.uuid import normalize_uuid
from aiohomekit.zeroconf import ZeroconfPairing

from .connection import CoAPHomeKitConnection

logger = logging.getLogger(__name__)


class CoAPPairing(ZeroconfPairing):
    def __init__(
        self, controller: AbstractController, pairing_data: AbstractPairingData
    ) -> None:
        self.connection = CoAPHomeKitConnection(
            self, pairing_data["AccessoryIP"], pairing_data["AccessoryPort"]
        )
        self.connection_future = None
        self.connection_lock = asyncio.Condition()
        self.pairing_data = pairing_data

        super().__init__(controller, pairing_data)

    def _async_endpoint_changed(self) -> None:
        """The IP/Port has changed, so close connection if active then reconnect."""
        self.connection.address = (
            f"[{self.description.address}]:{self.description.port}"
        )
        async_create_task(self.connection.reconnect_soon())

    @property
    def is_connected(self):
        return self.connection.is_connected

    @property
    def is_available(self) -> bool:
        """Returns true if the device is currently available."""
        return self.connection.is_connected

    @property
    def transport(self) -> Transport:
        """The transport used for the connection."""
        return Transport.COAP

    @property
    def name(self) -> str:
        """Return the name of the pairing with the address."""
        if self.description:
            return f"{self.description.name} [{self.connection.address}] (id={self.id})"
        return f"[{self.connection.address}] (id={self.id})"

    @property
    def poll_interval(self) -> timedelta:
        """Returns how often the device should be polled."""
        return timedelta(minutes=1)

    async def _ensure_connected(self):
        # let in one coroutine at a time
        async with self.connection_lock:
            if self._shutdown:
                return
            # are we already connected?
            if self.connection.is_connected:
                return

            # if there isn't a connection in progress, we're in the driver's seat
            if self.connection_future is None:
                # start a connection but don't await it here
                self.connection_future = self.connection.connect(self.pairing_data)
            else:
                # we'll wait on the primary coroutine & copy how it returns
                # this drops the lock and reacquires it when we're notified
                await self.connection_lock.wait()
                # if the primary coroutine failed to connect, we also raise
                if not self.connection.is_connected:
                    raise AccessoryDisconnectedError(
                        "primary coroutine failed to connect"
                    )
                return

        try:
            # await the connection outside of the lock
            # this allows other coroutines to show up & wait
            await self.connection_future
        except BaseException:
            raise AccessoryDisconnectedError("failed to connect")
        else:
            # in case this was a reconnect, re-subscribe
            if len(self.subscriptions):
                logger.debug(
                    "(Re-)subscribing to %d characteristics: %r"
                    % (len(self.subscriptions), self.subscriptions)
                )
                await self.connection.subscribe_to(list(self.subscriptions))
            self._callback_availability_changed(True)
        finally:
            # until we re-acquire the lock & clear connection_future,
            # other coroutines that show up will all hit the .wait() path.
            async with self.connection_lock:
                # clear the flag indicating a connection is in progress
                self.connection_future = None
                # wake up any coroutines that showed up while we were connecting
                self.connection_lock.notify_all()

        return

    async def close(self) -> None:
        if self.connection.is_connected:
            await self.unsubscribe(list(self.subscriptions))
        return

    def event_received(self, event):
        self._callback_listeners(event)

    async def identify(self):
        await self._ensure_connected()
        return await self.connection.do_identify()

    async def list_accessories_and_characteristics(self) -> list[dict[str, Any]]:
        await self._ensure_connected()

        accessories = await self.connection.get_accessory_info()

        for accessory in accessories:
            for service in accessory["services"]:
                service["type"] = normalize_uuid(service["type"])

                for characteristic in service["characteristics"]:
                    characteristic["type"] = normalize_uuid(characteristic["type"])

        self._accessories_state = AccessoriesState(
            Accessories.from_list(accessories), self.config_num or 0
        )
        self._update_accessories_state_cache()
        return accessories

    async def _process_config_changed(self, config_num: int) -> None:
        """Process a config change.

        This method is called when the config num changes.
        """
        await self.list_accessories_and_characteristics()
        self._accessories_state = AccessoriesState(
            self._accessories_state.accessories, config_num
        )
        self._callback_and_save_config_changed(config_num)

    async def _process_disconnected_events(self):
        """Process any events that happened while we were disconnected.

        We don't disconnect in COAP so there is no need to do anything here.
        """

    async def async_populate_accessories_state(
        self, force_update: bool = False, attempts: int | None = None
    ) -> bool:
        """Populate the state of all accessories.

        This method should try not to fetch all the accessories unless
        we know the config num is out of date or force_update is True
        """
        if not self.accessories or force_update:
            await self.list_accessories_and_characteristics()

    async def get_characteristics(
        self,
        characteristics,
    ):
        await self._ensure_connected()
        return await self.connection.read_characteristics(characteristics)

    async def put_characteristics(
        self, characteristics: Iterable[tuple[int, int, Any]]
    ) -> dict[tuple[int, int], dict[str, Any]]:
        await self._ensure_connected()
        response_status = await self.connection.write_characteristics(characteristics)

        listener_update: dict[tuple[int, int], dict[str, Any]] = {}
        for characteristic in characteristics:
            aid, iid, value = characteristic
            accessory_chars = self.accessories.aid(aid).characteristics
            char = accessory_chars.iid(iid)
            if (
                response_status.get((aid, iid), HapStatusCode.SUCCESS)
                == HapStatusCode.SUCCESS
                and CharacteristicPermissions.paired_read in char.perms
            ):
                listener_update[(aid, iid)] = {"value": value}

        if listener_update:
            self._callback_listeners(listener_update)

        return response_status

    async def thread_provision(
        self,
        dataset: str,
    ) -> None:
        """Provision a device with Thread network credentials."""

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

    async def remove_pairing(self, pairingId: str) -> bool:
        await self._ensure_connected()
        if await self.connection.remove_pairing(pairingId):
            await self._shutdown_if_primary_pairing_removed(pairingId)
            return True
        return False
