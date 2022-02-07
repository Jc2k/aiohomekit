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
import re
from typing import Iterable

from zeroconf.asyncio import AsyncZeroconf

from aiohomekit.characteristic_cache import (
    CharacteristicCacheMemory,
    CharacteristicCacheType,
)
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
    MalformedPinError,
    TransportNotSupportedError,
)
from .pairing import AbstractPairing

if COAP_TRANSPORT_SUPPORTED:
    from .coap import CoAPPairing

if IP_TRANSPORT_SUPPORTED:
    from .ip import IpController, IpPairing

if BLE_TRANSPORT_SUPPORTED:
    from aiohomekit.controller.ble import BleDiscovery, BlePairing


class Controller:
    """
    This class represents a HomeKit controller (normally your iPhone or iPad).
    """

    def __init__(
        self,
        async_zeroconf_instance: AsyncZeroconf | None = None,
        char_cache: CharacteristicCacheType | None = None,
    ) -> None:
        """
        Initialize an empty controller. Use 'load_data()' to load the pairing data.

        :param ble_adapter: the bluetooth adapter to be used (defaults to hci0)
        """
        self.pairings = {}
        self._async_zeroconf_instance = async_zeroconf_instance
        self._char_cache = char_cache or CharacteristicCacheMemory()

        self._transports = []
        self._tasks = AsyncExitStack()

    async def __aenter__(self):
        await self.async_start()

    async def __aexit__(self, *args):
        await self.async_stop()

    async def async_start(self):
        if IP_TRANSPORT_SUPPORTED:
            self._transports.append(
                await self._tasks.enter_async_context(
                    IpController(self._async_zeroconf_instance)
                )
            )

        if COAP_TRANSPORT_SUPPORTED:
            self._transports.append(
                await self._tasks.enter_async_context(
                    CoAPController(self._async_zeroconf_instance)
                )
            )

        if BLE_TRANSPORT_SUPPORTED:
            self._transports.append(
                await self._tasks.enter_async_context(BleController())
            )

    async def async_stop(self):
        await self._tasks.aclose()

    async def discover(self, max_seconds=10) -> Iterable[BleDiscovery]:
        for transport in self._transports:
            for device in transport.devices.values():
                yield device

        """
        # Backwards compact
        if not device_id.startswith("hap+"):
            device_id = "hap+ip://"

        parsed = urlparse(device_id)

        if parsed.scheme == "hap+ip":
            if not IP_TRANSPORT_SUPPORTED:
                raise TransportNotSupportedError("IP")

            device = await async_find_data_for_device_id(
                device_id=parsed.netloc,
                max_seconds=max_seconds,
                async_zeroconf_instance=self._async_zeroconf_instance,
            )
            return IpDiscovery(self, device)

        if parsed.scheme == "hap+ble":
            if not BLE_TRANSPORT_SUPPORTED:
                raise TransportNotSupportedError("BLE")

            device = await BleakScanner.find_device_by_address(
                parsed.netloc, timeout=max_seconds
            )
            if not device:
                raise AccessoryNotFoundError(
                    f"Device not found via BLE discovery within {max_seconds}s"
                )

            return BleDiscovery(self, device)
        """

    async def shutdown(self) -> None:
        """
        Shuts down the controller by closing all connections that might be held open by the pairings of the controller.
        """
        for p in self.pairings:
            await self.pairings[p].close()

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

    def get_pairings(self) -> dict[str, AbstractPairing]:
        """
        Returns a dict containing all pairings known to the controller.

        :return: the dict maps the aliases to Pairing objects
        """
        return self.pairings

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

    @staticmethod
    def check_pin_format(pin: str) -> None:
        """
        Checks the format of the given pin: XXX-XX-XXX with X being a digit from 0 to 9

        :raises MalformedPinError: if the validation fails
        """
        if not re.match(r"^\d\d\d-\d\d-\d\d\d$", pin):
            raise MalformedPinError(
                "The pin must be of the following XXX-XX-XXX where X is a digit between 0 and 9."
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
