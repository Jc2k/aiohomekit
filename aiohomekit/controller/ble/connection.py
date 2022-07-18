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

from bleak.backends.device import BLEDevice

from aiohomekit.exceptions import AccessoryDisconnectedError, AccessoryNotFoundError

from .bleak import BLEAK_EXCEPTIONS, AIOHomeKitBleakClient

logger = logging.getLogger(__name__)

MAX_TRANSIENT_ERRORS = 9

# Shorter time outs and more attempts
# seems to be better for dbus, and corebluetooth
# is happy either way. Ideally we want everything
# to finish in < 60s or declare we cannot connect

MAX_CONNECT_ATTEMPTS = 5
BLEAK_TIMEOUT = 10

TRANSIENT_ERRORS = {"le-connection-abort-by-local", "br-connection-canceled"}


async def establish_connection(
    device: BLEDevice,
    name: str,
    disconnected_callback: Callable[[AIOHomeKitBleakClient], None],
    max_attempts: int = MAX_CONNECT_ATTEMPTS,
) -> AIOHomeKitBleakClient:
    """Establish a connection to the accessory."""
    timeouts = 0
    connect_errors = 0
    transient_errors = 0
    attempt = 0

    client = AIOHomeKitBleakClient(device)
    client.set_disconnected_callback(disconnected_callback)

    def _raise_if_needed(name: str, exc: Exception) -> None:
        """Raise if we reach the max attempts."""
        if (
            timeouts + connect_errors < max_attempts
            and transient_errors < MAX_TRANSIENT_ERRORS
        ):
            return
        msg = f"{name}: Failed to connect: {exc}"
        # Sure would be nice if bleak gave us typed exceptions
        if isinstance(exc, asyncio.TimeoutError) or "not found" in str(exc):
            raise AccessoryNotFoundError(msg) from exc
        raise AccessoryDisconnectedError(msg) from exc

    while True:
        attempt += 1
        logger.debug("%s: Connecting (attempt: %s)", name, attempt)
        try:
            await client.connect(timeout=BLEAK_TIMEOUT)
        except asyncio.TimeoutError as exc:
            timeouts += 1
            logger.debug("%s: Timed out trying to connect (attempt: %s)", name, attempt)
            _raise_if_needed(name, exc)
        except BLEAK_EXCEPTIONS as exc:
            bleak_error = str(exc)
            if any(error in bleak_error for error in TRANSIENT_ERRORS):
                transient_errors += 1
            else:
                connect_errors += 1
            logger.debug(
                "%s: Failed to connect: %s (attempt: %s)", name, str(exc), attempt
            )
            _raise_if_needed(name, exc)
        else:
            logger.debug("%s: Connected (attempt: %s)", name, attempt)
            return client

    raise RuntimeError("This should never happen")
