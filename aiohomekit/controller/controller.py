#
# Copyright 2019 aiohomekit team
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

from contextlib import AsyncExitStack
import json
from json.decoder import JSONDecodeError
import pathlib
from typing import AsyncIterable

from zeroconf.asyncio import AsyncZeroconf

from aiohomekit.characteristic_cache import (
    CharacteristicCacheMemory,
    CharacteristicCacheType,
)
from aiohomekit.controller.abstract import AbstractDiscovery
from aiohomekit.controller.ble.controller import BleController
from aiohomekit.controller.coap.controller import CoAPController

from ..const import (
    BLE_TRANSPORT_SUPPORTED,
    COAP_TRANSPORT_SUPPORTED,
    IP_TRANSPORT_SUPPORTED,
)
from ..exceptions import (
    AccessoryNotFoundError,
    ConfigLoadingError,
    ConfigSavingError,
    TransportNotSupportedError,
)
from .abstract import AbstractController, AbstractPairing

if COAP_TRANSPORT_SUPPORTED:
    from .coap import CoAPPairing

if IP_TRANSPORT_SUPPORTED:
    from .ip import IpController, IpPairing

if BLE_TRANSPORT_SUPPORTED:
    from aiohomekit.controller.ble import BlePairing


class Controller(AbstractController):
    """
    This class represents a HomeKit controller (normally your iPhone or iPad).
    """

    pairings: dict[str, AbstractPairing]

    def __init__(
        self,
        async_zeroconf_instance: AsyncZeroconf | None = None,
        char_cache: CharacteristicCacheType | None = None,
    ) -> None:
        """
        Initialize an empty controller. Use 'load_data()' to load the pairing data.

        :param ble_adapter: the bluetooth adapter to be used (defaults to hci0)
        """
        super().__init__(char_cache=char_cache or CharacteristicCacheMemory())

        self._async_zeroconf_instance = async_zeroconf_instance

        self._transports: list[AbstractController] = []
        self._tasks = AsyncExitStack()

    async def _async_register_backend(self, controller: AbstractController):
        self._transports.append(await self._tasks.enter_async_context(controller))

    async def async_start(self):
        if IP_TRANSPORT_SUPPORTED:
            await self._async_register_backend(
                IpController(
                    char_cache=self._char_cache,
                    zeroconf_instance=self._async_zeroconf_instance,
                )
            )

        if COAP_TRANSPORT_SUPPORTED:
            await self._async_register_backend(
                CoAPController(
                    char_cache=self._char_cache,
                    zeroconf_instance=self._async_zeroconf_instance,
                )
            )

        if BLE_TRANSPORT_SUPPORTED:
            await self._async_register_backend(
                BleController(char_cache=self._char_cache)
            )

    async def async_stop(self):
        await self._tasks.aclose()

        # for p in self.pairings:
        #    await self.pairings[p].close()

    async def async_find(self, device_id: str) -> AbstractDiscovery:
        for transport in self._transports:
            if device_id in transport.discoveries:
                return transport.discoveries[device_id]

        raise AccessoryNotFoundError(f"Accessory with device id {device_id} not found")

    async def async_discover(self, timeout=10) -> AsyncIterable[AbstractDiscovery]:
        for transport in self._transports:
            for device in transport.discoveries.values():
                yield device

    def load_pairing(self, alias: str, pairing_data: dict[str, str]) -> AbstractPairing:
        """
        Loads a pairing instance from a pairing data dict.
        """
        if "Connection" not in pairing_data:
            pairing_data["Connection"] = "IP"

        if pairing_data["Connection"] == "IP":
            if not IP_TRANSPORT_SUPPORTED:
                raise TransportNotSupportedError("IP")
            pairing = self.pairings[alias] = IpPairing(self, pairing_data)
            return pairing

        if pairing_data["Connection"] == "CoAP":
            if not COAP_TRANSPORT_SUPPORTED:
                raise TransportNotSupportedError("CoAP")
            pairing = self.pairings[alias] = CoAPPairing(self, pairing_data)
            return pairing

        if pairing_data["Connection"] == "BLE":
            if not BLE_TRANSPORT_SUPPORTED:
                raise TransportNotSupportedError("BLE")

            pairing = self.pairings[alias] = BlePairing(self, pairing_data)
            return pairing

        connection_type = pairing_data["Connection"]
        raise NotImplementedError(f"{connection_type} support")

    def load_data(self, filename: str) -> None:
        """
        Loads the pairing data of the controller from a file.

        :param filename: the file name of the pairing data
        :raises ConfigLoadingError: if the config could not be loaded. The reason is given in the message.
        """
        try:
            with open(filename) as input_fp:
                data = json.load(input_fp)
                for pairing_id in data:
                    self.load_pairing(pairing_id, data[pairing_id])
        except PermissionError:
            raise ConfigLoadingError(
                f'Could not open "{filename}" due to missing permissions'
            )
        except JSONDecodeError:
            raise ConfigLoadingError(f'Cannot parse "{filename}" as JSON file')
        except FileNotFoundError:
            pass

    def save_data(self, filename: str) -> None:
        """
        Saves the pairing data of the controller to a file.

        :param filename: the file name of the pairing data
        :raises ConfigSavingError: if the config could not be saved. The reason is given in the message.
        """
        data = {}
        for pairing_id in self.pairings:
            # package visibility like in java would be nice here
            data[pairing_id] = self.pairings[pairing_id].pairing_data

        path = pathlib.Path(filename)

        if not path.parent.exists():
            path.parent.mkdir(parents=True, exist_ok=True)

        try:
            with open(filename, "w") as output_fp:
                json.dump(data, output_fp, indent="  ")
        except PermissionError:
            raise ConfigSavingError(
                f'Could not write "{filename}" due to missing permissions'
            )
        except FileNotFoundError:
            raise ConfigSavingError(
                'Could not write "{f}" because it (or the folder) does not exist'.format(
                    f=filename
                )
            )

    async def remove_pairing(self, alias: str) -> None:
        """
        Remove a pairing between the controller and the accessory. The pairing data is delete on both ends, on the
        accessory and the controller.

        Important: no automatic saving of the pairing data is performed. If you don't do this, the accessory seems still
            to be paired on the next start of the application.

        :param alias: the controller's alias for the accessory
        :raises AuthenticationError: if the controller isn't authenticated to the accessory.
        :raises AccessoryNotFoundError: if the device can not be found via zeroconf
        :raises UnknownError: on unknown errors
        """
        if alias not in self.pairings:
            raise AccessoryNotFoundError(f'Alias "{alias}" is not found.')

        pairing = self.pairings[alias]

        primary_pairing_id = pairing.pairing_data["iOSPairingId"]
        await pairing.remove_pairing(primary_pairing_id)

        await pairing.close()

        self._char_cache.async_delete_map(primary_pairing_id)

        del self.pairings[alias]
