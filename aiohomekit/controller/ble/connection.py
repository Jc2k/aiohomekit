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
from collections.abc import Callable
import logging

from bleak.exc import BleakError

from aiohomekit.exceptions import AccessoryDisconnectedError

from .client import AIOHomeKitBleakClient

logger = logging.getLogger(__name__)

MAX_CONNECT_ATTEMPTS = 4


async def establish_connection(
    client: AIOHomeKitBleakClient | None,
    name: str,
    address_callback: Callable[[None], str],
    disconnected_callback: Callable[[AIOHomeKitBleakClient], None],
    max_attempts: int = MAX_CONNECT_ATTEMPTS,
) -> AIOHomeKitBleakClient:
    """Establish a connection to the accessory."""
    attempts = 0
    while True:
        attempts += 1
        address = address_callback()
        if not client or client.address != address:
            # Only replace the client if the address has changed
            client = AIOHomeKitBleakClient(address)
            client.set_disconnected_callback(disconnected_callback)

        logger.debug("%s: Connecting", name)
        try:
            await client.connect()
        except (asyncio.TimeoutError, BleakError, AttributeError) as e:
            logger.debug("Failed to connect to %s: %s", name, str(e))
        else:
            logger.debug("%s: Connected", name)
            return client

        if attempts == max_attempts:
            break
        await asyncio.sleep(5)

    raise AccessoryDisconnectedError(f"Failed to connect to {name}")
