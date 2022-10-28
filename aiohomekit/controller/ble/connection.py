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

from collections.abc import Callable

from bleak.backends.device import BLEDevice
from bleak_retry_connector import (
    BleakAbortedError,
    BleakConnectionError,
    BleakError,
    BleakNotFoundError,
    establish_connection as retry_establish_connection,
)

from aiohomekit.exceptions import AccessoryDisconnectedError, AccessoryNotFoundError

from .bleak import AIOHomeKitBleakClient

MAX_CONNECT_ATTEMPTS = 5


async def establish_connection(
    device: BLEDevice,
    name: str,
    disconnected_callback: Callable[[AIOHomeKitBleakClient], None],
    max_attempts: int | None = None,
    use_services_cache: bool = False,
    ble_device_callback: Callable[[BLEDevice], None] = None,
) -> AIOHomeKitBleakClient:
    """Establish a connection to the accessory."""
    try:
        return await retry_establish_connection(
            AIOHomeKitBleakClient,
            device,
            name,
            disconnected_callback,
            max_attempts=max_attempts or MAX_CONNECT_ATTEMPTS,
            use_services_cache=use_services_cache,
            ble_device_callback=ble_device_callback,
        )
    except (BleakAbortedError, BleakConnectionError) as ex:
        raise AccessoryDisconnectedError(ex) from ex
    except BleakNotFoundError as ex:
        raise AccessoryNotFoundError(ex) from ex
    except BleakError as ex:
        raise AccessoryDisconnectedError(ex) from ex
