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
from typing import AsyncIterable, Awaitable, Callable, Protocol, final

from aiohomekit.characteristic_cache import CharacteristicCacheType
from aiohomekit.model.categories import Categories
from aiohomekit.model.status_flags import StatusFlags


class AbstractDescription(Protocol):

    name: str
    id: str
    model: str
    status_flags: StatusFlags
    config_num: int
    state_num: int
    category: Categories


class AbstractPairing(metaclass=ABCMeta):

    # The current discovery information for this pairing.
    # This can be used to detect address changes, s# changes, c# changes, etc
    description: AbstractDescription | None = None

    # The normalised (lower case) form of the device id (as seen in zeroconf
    # and BLE advertisements), and also as AccessoryPairingID i pairing data.
    id: str

    def __init__(self, controller):
        self.controller = controller
        self.listeners = set()
        self.subscriptions = set()

    def _async_description_update(self, description: AbstractDescription | None):
        self.description = description

    @property
    @abstractmethod
    def is_connected(self) -> bool:
        """
        Returns true if the device is currently connected.
        """
        pass

    @abstractmethod
    async def close(self):
        pass

    @abstractmethod
    async def list_accessories_and_characteristics(self):
        pass

    @abstractmethod
    async def list_pairings(self):
        pass

    @abstractmethod
    async def get_characteristics(
        self,
        characteristics,
        include_meta=False,
        include_perms=False,
        include_type=False,
        include_events=False,
    ):
        pass

    @abstractmethod
    async def put_characteristics(self, characteristics):
        pass

    @abstractmethod
    async def identify(self):
        pass

    @abstractmethod
    async def remove_pairing(self, pairing_id: str) -> None:
        pass

    async def subscribe(self, characteristics):
        new_characteristics = set(characteristics) - self.subscriptions
        self.subscriptions.update(characteristics)
        return new_characteristics

    async def unsubscribe(self, characteristics):
        self.subscriptions.difference_update(characteristics)

    async def reconnect_soon(self):
        """
        Notify the pairing that we have noticed a network change that means its connection maybe stale.

        This will be removed in a future release.
        """
        pass

    def dispatcher_connect(self, callback):
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
        pass

    @abstractmethod
    async def async_identify(self) -> None:
        pass


class AbstractController(metaclass=ABCMeta):

    discoveries: dict[str, AbstractDiscovery]
    pairings: dict[str, AbstractPairing]
    aliases: dict[str, AbstractPairing]

    def __init__(self, char_cache: CharacteristicCacheType):
        self.pairings = {}
        self.aliases = {}
        self.discoveries = {}

        self._char_cache = char_cache

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
        pass

    @abstractmethod
    async def async_discover(self, timeout=10) -> AsyncIterable[AbstractDiscovery]:
        pass

    @abstractmethod
    async def async_start(self) -> None:
        pass

    @abstractmethod
    async def async_stop(self) -> None:
        pass

    @abstractmethod
    def load_pairing(self, alias: str, pairing_data: dict[str, str]) -> AbstractPairing:
        pass
