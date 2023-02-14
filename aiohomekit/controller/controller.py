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

import asyncio
from asyncio.log import logger
from collections.abc import AsyncIterable
from contextlib import AsyncExitStack
import pathlib

from bleak import BleakScanner
from zeroconf.asyncio import AsyncZeroconf

from aiohomekit.characteristic_cache import (
    CharacteristicCacheMemory,
    CharacteristicCacheType,
)
from aiohomekit.controller.abstract import AbstractDiscovery
import aiohomekit.hkjson as hkjson

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
from .abstract import AbstractController, AbstractPairing, TransportType


class Controller(AbstractController):
    """
    This class represents a HomeKit controller (normally your iPhone or iPad).
    """

    pairings: dict[str, AbstractPairing]

    def __init__(
        self,
        async_zeroconf_instance: AsyncZeroconf | None = None,
        char_cache: CharacteristicCacheType | None = None,
        bleak_scanner_instance: BleakScanner | None = None,
    ) -> None:
        """
        Initialize an empty controller. Use 'load_data()' to load the pairing data.

        :param ble_adapter: the bluetooth adapter to be used (defaults to hci0)
        """
        super().__init__(char_cache=char_cache or CharacteristicCacheMemory())

        self._async_zeroconf_instance = async_zeroconf_instance
        self._bleak_scanner_instance = bleak_scanner_instance

        self.transports: dict[TransportType, AbstractController] = {}
        self._tasks = AsyncExitStack()

    async def _async_register_backend(self, controller: AbstractController) -> None:
        self.transports[
            controller.transport_type
        ] = await self._tasks.enter_async_context(controller)

    async def async_start(self) -> None:
        if IP_TRANSPORT_SUPPORTED or self._async_zeroconf_instance:
            from .ip.controller import (
                IpController,  # pylint: disable=import-outside-toplevel
            )

            await self._async_register_backend(
                IpController(
                    char_cache=self._char_cache,
                    zeroconf_instance=self._async_zeroconf_instance,
                )
            )

        if COAP_TRANSPORT_SUPPORTED:
            from .coap.controller import (
                CoAPController,  # pylint: disable=import-outside-toplevel
            )

            await self._async_register_backend(
                CoAPController(
                    char_cache=self._char_cache,
                    zeroconf_instance=self._async_zeroconf_instance,
                )
            )

        if BLE_TRANSPORT_SUPPORTED or self._bleak_scanner_instance:
            from .ble.controller import (
                BleController,  # pylint: disable=import-outside-toplevel
            )

            await self._async_register_backend(
                BleController(
                    char_cache=self._char_cache,
                    bleak_scanner_instance=self._bleak_scanner_instance,
                )
            )

    async def async_stop(self) -> None:
        await self._tasks.aclose()

    async def async_find(
        self, device_id: str, timeout: float = 30.0
    ) -> AbstractDiscovery:
        pending = []
        for transport in self.transports.values():
            pending.append(
                asyncio.create_task(transport.async_find(device_id, timeout))
            )

        try:
            while pending:
                done, pending = await asyncio.wait(
                    pending, return_when=asyncio.FIRST_COMPLETED
                )
                for result in done:
                    try:
                        return result.result()
                    except AccessoryNotFoundError:
                        continue
        finally:
            [task.cancel() for task in pending]
            for task in pending:
                try:
                    await task
                except asyncio.CancelledError:
                    pass

        raise AccessoryNotFoundError(f"Accessory with device id {device_id} not found")

    async def async_discover(self, timeout=10) -> AsyncIterable[AbstractDiscovery]:
        for transport in self.transports.values():
            async for device in transport.async_discover():
                yield device

    def load_pairing(self, alias: str, pairing_data: dict[str, str]) -> AbstractPairing:
        """
        Loads a pairing instance from a pairing data dict.
        """
        if "Connection" not in pairing_data:
            pairing_data["Connection"] = "IP"

        for transport in self.transports.values():
            if pairing := transport.load_pairing(alias, pairing_data):
                self.pairings[pairing_data["AccessoryPairingID"].lower()] = pairing
                self.aliases[alias] = pairing
                return pairing

        raise TransportNotSupportedError(pairing_data["Connection"])

    def load_data(self, filename: str) -> None:
        """
        Loads the pairing data of the controller from a file.

        :param filename: the file name of the pairing data
        :raises ConfigLoadingError: if the config could not be loaded. The reason is given in the message.
        """
        try:
            with open(filename, encoding="utf-8") as input_fp:
                data = hkjson.loads(input_fp.read())
                for pairing_id in data:
                    try:
                        self.load_pairing(pairing_id, data[pairing_id])
                    except TransportNotSupportedError as e:
                        logger.error("Skipped pairing: %s", e)
        except PermissionError:
            raise ConfigLoadingError(
                f'Could not open "{filename}" due to missing permissions'
            )
        except hkjson.JSON_DECODE_EXCEPTIONS as e:
            raise ConfigLoadingError(f'Cannot parse "{filename}" as JSON file') from e
        except FileNotFoundError:
            pass

    def save_data(self, filename: str) -> None:
        """
        Saves the pairing data of the controller to a file.

        :param filename: the file name of the pairing data
        :raises ConfigSavingError: if the config could not be saved. The reason is given in the message.
        """
        data = {}
        for alias in self.aliases:
            data[alias] = self.aliases[alias].pairing_data

        path = pathlib.Path(filename)

        if not path.parent.exists():
            path.parent.mkdir(parents=True, exist_ok=True)

        try:
            with open(filename, mode="w", encoding="utf-8") as output_fp:
                output_fp.write(hkjson.dumps_indented(data))
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
        if alias not in self.aliases:
            raise AccessoryNotFoundError(f'Alias "{alias}" is not found.')

        pairing = self.aliases[alias]

        try:
            # Remove the pairing from the controller first
            # so that it stops getting updates that might
            # trigger a disconnected event poll.
            self.aliases.pop(alias, None)
            pairing.controller.aliases.pop(alias, None)

            self.pairings.pop(pairing.id, None)
            pairing.controller.pairings.pop(pairing.id, None)

            primary_pairing_id = pairing.pairing_data["iOSPairingId"]

            await pairing.remove_pairing(primary_pairing_id)

            await pairing.close()

        finally:
            self._char_cache.async_delete_map(pairing.id)
