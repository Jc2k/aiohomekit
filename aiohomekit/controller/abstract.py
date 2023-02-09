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

from abc import ABCMeta, abstractmethod
from collections.abc import AsyncIterable, Awaitable, Iterable
from dataclasses import dataclass
from datetime import timedelta
from enum import Enum
import logging
from typing import Any, Callable, TypedDict, final

from aiohomekit.characteristic_cache import CharacteristicCacheType
from aiohomekit.model import Accessories, AccessoriesState, Transport
from aiohomekit.model.categories import Categories
from aiohomekit.model.characteristics.characteristic_types import CharacteristicsTypes
from aiohomekit.model.services.service_types import ServicesTypes
from aiohomekit.model.status_flags import StatusFlags
from aiohomekit.utils import (
    async_create_task,
    deserialize_broadcast_key,
    serialize_broadcast_key,
)

logger = logging.getLogger(__name__)


class AbstractPairingData(TypedDict, total=False):

    AccessoryPairingID: str
    AccessoryLTPK: str
    iOSPairingId: str
    iOSDeviceLTSK: str
    iOSDeviceLTPK: str
    AccessoryAddress: str
    Connection: str


@dataclass
class AbstractDescription:

    name: str
    id: str
    status_flags: StatusFlags
    config_num: int
    category: Categories


class TransportType(Enum):

    IP = "ip"
    COAP = "coap"
    BLE = "ble"


class AbstractPairing(metaclass=ABCMeta):

    # The current discovery information for this pairing.
    # This can be used to detect address changes, s# changes, c# changes, etc
    description: AbstractDescription | None = None

    # The normalised (lower case) form of the device id (as seen in zeroconf
    # and BLE advertisements), and also as AccessoryPairingID i pairing data.
    id: str

    def __init__(
        self, controller: AbstractController, pairing_data: AbstractPairingData
    ) -> None:
        self.controller = controller
        self.listeners: set[Callable[[dict], None]] = set()
        self.subscriptions: set[tuple[int, int]] = set()
        self.availability_listeners: set[Callable[[bool], None]] = set()
        self.config_changed_listeners: set[Callable[[int], None]] = set()
        self._accessories_state: AccessoriesState | None = None
        self._shutdown = False

        self.id = pairing_data["AccessoryPairingID"]
        self._pairing_data = pairing_data
        self._load_accessories_from_cache()

    @property
    def accessories_state(self) -> AccessoriesState:
        """Return the current state of the accessories."""
        return self._accessories_state

    @property
    def accessories(self) -> Accessories | None:
        """Wrapper around the accessories state to make it easier to use."""
        if not self._accessories_state:
            return None
        return self._accessories_state.accessories

    @property
    def config_num(self) -> int:
        """Wrapper around the accessories state to make it easier to use."""
        if not self._accessories_state:
            return -1
        return self._accessories_state.config_num

    @property
    def name(self) -> str:
        """Return the name of the pairing."""
        if self.description:
            return f"{self.description.name} (id={self.id})"
        return f"(id={self.id})"

    @property
    @abstractmethod
    def is_connected(self) -> bool:
        """Returns true if the device is currently connected."""

    @property
    @abstractmethod
    def is_available(self) -> bool:
        """Returns true if the device is currently available."""

    @property
    @abstractmethod
    def transport(self) -> Transport:
        """The transport used for the connection."""

    @property
    @abstractmethod
    def poll_interval(self) -> timedelta:
        """Returns how often the device should be polled."""

    @property
    def broadcast_key(self) -> bytes | None:
        """Returns the broadcast key."""
        if not self._accessories_state:
            return None
        return self._accessories_state.broadcast_key

    @property
    def state_num(self) -> bytes | None:
        """Returns gsn that is saved between restarts."""
        if not self._accessories_state:
            return None
        return self._accessories_state.state_num

    @abstractmethod
    async def _process_disconnected_events(self):
        """Process any disconnected events that are available."""

    def _callback_listeners(self, event):
        for listener in self.listeners:
            try:
                logger.debug("callback ev:%s", event)
                listener(event)
            except Exception:
                logger.exception("Unhandled error when processing event")

    def _async_description_update(
        self, description: AbstractDescription | None
    ) -> None:
        if self._shutdown:
            return

        if self.description != description:
            logger.debug(
                "%s: Description updated: old=%s new=%s",
                self.name,
                self.description,
                description,
            )

        repopulate_accessories = False
        if description:
            if description.config_num > self.config_num:
                logger.debug(
                    "%s: Config number has changed from %s to %s; char cache invalid",
                    self.name,
                    self.config_num,
                    description.config_num,
                )
                repopulate_accessories = True

            elif (
                not self.description
                or description.state_num != self.description.state_num
            ):
                # Only process disconnected events if the config number has
                # not also changed since we will do a full repopulation
                # of the accessories anyway when the config number changes.
                #
                # Otherwise, if only the state number we trigger a poll.
                #
                # The number will eventually roll over
                # so we don't want to use a > comparison here. Also, its
                # safer to poll the device again to get the latest state
                # as we don't want to miss events.
                logger.debug(
                    "%s: Disconnected event notification received; Triggering catch-up poll",
                    self.name,
                )
                async_create_task(self._process_disconnected_events())

        self.description = description

        if repopulate_accessories:
            async_create_task(self._process_config_changed(description.config_num))

    def _load_accessories_from_cache(self) -> None:
        if (cache := self.controller._char_cache.get_map(self.id)) is None:
            logger.debug(
                "%s: No accessories cache available for this device", self.name
            )
            return
        config_num = cache.get("config_num", 0)
        state_num = cache.get("state_num")
        broadcast_key_hex = cache.get("broadcast_key")
        accessories = Accessories.from_list(cache["accessories"])
        self._accessories_state = AccessoriesState(
            accessories,
            config_num,
            deserialize_broadcast_key(broadcast_key_hex),
            state_num,
        )
        logger.debug(
            "%s: Accessories cache loaded (c#: %d) (gsn: %s) (has broadcast_key: %s)",
            self.name,
            config_num,
            state_num,  # May be None
            bool(broadcast_key_hex),
        )

    def restore_accessories_state(
        self,
        accessories: list[dict[str, Any]],
        config_num: int,
        broadcast_key: bytes | None,
        state_num: int | None = None,
    ) -> None:
        """Restore accessories from cache."""
        accessories = Accessories.from_list(accessories)
        self._accessories_state = AccessoriesState(
            accessories, config_num, broadcast_key, state_num
        )
        self._update_accessories_state_cache()

    def _update_accessories_state_cache(self):
        """Update the cache with the current state of the accessories."""
        self.controller._char_cache.async_create_or_update_map(
            self.id,
            self.config_num,
            self.accessories.serialize(),
            serialize_broadcast_key(self.broadcast_key),
            self.state_num,
        )

    async def get_primary_name(self) -> str:
        """Return the primary name of the device."""
        if not self.accessories:
            accessories = await self.list_accessories_and_characteristics()
            parsed = Accessories.from_list(accessories)
        else:
            parsed = self.accessories

        accessory_info = parsed.aid(1).services.first(
            service_type=ServicesTypes.ACCESSORY_INFORMATION
        )
        return accessory_info.value(CharacteristicsTypes.NAME, "")

    @abstractmethod
    async def thread_provision(
        self,
        dataset: str,
    ) -> None:
        """Provision a device with Thread network credentials."""

    @abstractmethod
    async def async_populate_accessories_state(
        self, force_update: bool = False, attempts: int | None = None
    ) -> None:
        """Populate the state of all accessories.

        This method should try not to fetch all the accessories unless
        we know the config num is out of date or force_update is True
        """

    @abstractmethod
    async def close(self) -> None:
        """Close the connection."""

    @abstractmethod
    async def list_accessories_and_characteristics(self) -> list[dict[str, Any]]:
        """List all accessories and characteristics."""

    @abstractmethod
    async def list_pairings(self):
        """List pairings."""

    @abstractmethod
    async def get_characteristics(
        self,
        characteristics,
        include_meta=False,
        include_perms=False,
        include_type=False,
        include_events=False,
    ):
        """Get characteristics."""

    @abstractmethod
    async def put_characteristics(self, characteristics):
        """Put characteristics."""

    @abstractmethod
    async def identify(self):
        """Identify the device."""

    @abstractmethod
    async def remove_pairing(self, pairing_id: str) -> None:
        """Remove a pairing."""

    @abstractmethod
    async def _process_config_changed(self, config_num: int) -> None:
        """Process a config change.

        This method is called when the config num changes.
        """

    async def _shutdown_if_primary_pairing_removed(self, pairingId: str) -> None:
        """Shutdown the connection if the primary pairing was removed."""
        if pairingId == self._pairing_data.get("iOSPairingId"):
            await self.shutdown()

    async def shutdown(self) -> None:
        """Shutdown the pairing.

        This method is irreversible. It should be called when
        the pairing is removed or the controller is shutdown.
        """
        self._shutdown = True
        await self.close()

    def _callback_availability_changed(self, available: bool) -> None:
        """Notify availability changed listeners."""
        for callback in self.availability_listeners:
            callback(available)

    def _callback_and_save_config_changed(self, _config_num: int) -> None:
        """Notify config changed listeners and save the config."""
        for callback in self.config_changed_listeners:
            callback(self.config_num)
        self._update_accessories_state_cache()

    async def subscribe(
        self, characteristics: Iterable[tuple[int, int]]
    ) -> set[tuple[int, int]]:
        new_characteristics = set(characteristics) - self.subscriptions
        self.subscriptions.update(characteristics)
        return new_characteristics

    async def unsubscribe(self, characteristics: Iterable[tuple[int, int]]) -> None:
        self.subscriptions.difference_update(characteristics)

    def dispatcher_availability_changed(
        self, callback: Callable[[bool], None]
    ) -> Callable[[], None]:
        """Notify subscribers when availablity changes.

        Currently this only notifies when a device is seen as available and
        not when it is seen as unavailable.
        """
        self.availability_listeners.add(callback)

        def stop_listening():
            self.availability_listeners.discard(callback)

        return stop_listening

    def dispatcher_connect_config_changed(
        self, callback: Callable[[int], None]
    ) -> Callable[[], None]:
        """Notify subscribers of a new accessories state."""
        self.config_changed_listeners.add(callback)

        def stop_listening():
            self.config_changed_listeners.discard(callback)

        return stop_listening

    def dispatcher_connect(
        self, callback: Callable[[dict], None]
    ) -> Callable[[], None]:
        """
        Register an event handler to be called when a characteristic (or multiple characteristics) change.

        This function returns immediately. It returns a callable you can use to cancel the subscription.

        The callback is called in the event loop, but should not be a coroutine.
        """
        self.listeners.add(callback)

        def stop_listening():
            self.listeners.discard(callback)

        return stop_listening


FinishPairing = Callable[[str], Awaitable[AbstractPairing]]


class AbstractDiscovery(metaclass=ABCMeta):

    description: AbstractDescription

    @final
    @property
    def paired(self) -> bool:
        return not (self.description.status_flags & StatusFlags.UNPAIRED)

    @abstractmethod
    async def async_start_pairing(self, alias: str) -> FinishPairing:
        """Start pairing."""

    @abstractmethod
    async def async_identify(self) -> None:
        """Do an unpaired identify."""


class AbstractController(metaclass=ABCMeta):

    discoveries: dict[str, AbstractDiscovery]
    pairings: dict[str, AbstractPairing]
    aliases: dict[str, AbstractPairing]

    def __init__(self, char_cache: CharacteristicCacheType) -> None:
        self.pairings = {}
        self.aliases = {}
        self.discoveries = {}

        self._char_cache = char_cache

    @property
    def transport_type(self) -> TransportType:
        raise NotImplementedError(self.transport_type)

    @final
    async def __aenter__(self):
        await self.async_start()
        return self

    @final
    async def __aexit__(self, *args):
        await self.async_stop()

    """
    @abstractmethod
    async def async_open_session(device_id: str) -> AbstractPairing:
        pass
    """

    @abstractmethod
    async def async_find(self, device_id: str, timeout=10) -> AbstractDiscovery:
        """Find a device by id."""

    @abstractmethod
    async def async_discover(self, timeout=10) -> AsyncIterable[AbstractDiscovery]:
        """Discover all devices."""

    @abstractmethod
    async def async_start(self) -> None:
        """Start the controller."""

    @abstractmethod
    async def async_stop(self) -> None:
        """Stop the controller."""

    @abstractmethod
    def load_pairing(self, alias: str, pairing_data: dict[str, str]) -> AbstractPairing:
        """Load a pairing from data."""
