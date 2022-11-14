from __future__ import annotations

import asyncio
from collections.abc import Awaitable
import enum
import logging
import re
import sys
from typing import TypeVar

from aiohomekit.const import COAP_TRANSPORT_SUPPORTED, IP_TRANSPORT_SUPPORTED
from aiohomekit.exceptions import MalformedPinError
from aiohomekit.model.characteristics import Characteristic
from aiohomekit.model.feature_flags import FeatureFlags

_LOGGER = logging.getLogger(__name__)

T = TypeVar("T")

if sys.version_info[:2] < (3, 11):
    from async_timeout import timeout as asyncio_timeout  # noqa: F401
else:
    from asyncio import timeout as asyncio_timeout  # noqa: F401


def async_create_task(coroutine: Awaitable[T], *, name=None) -> asyncio.Task[T]:
    """Wrapper for asyncio.create_task that logs errors."""
    task = asyncio.create_task(coroutine, name=name)
    task.add_done_callback(_handle_task_result)
    return task


def _handle_task_result(task: asyncio.Task) -> None:
    try:
        task.result()
    except asyncio.CancelledError:
        # Ignore cancellations
        pass
    except Exception:
        _LOGGER.exception("Failure running background task: %s", task.get_name())


def clamp_enum_to_char(all_valid_values: enum.EnumMeta, char: Characteristic):
    """Clamp possible values of an enum to restrictions imposed by a manufacturer."""
    valid_values = set(all_valid_values)

    if char.minValue is not None:
        valid_values = {
            target_state
            for target_state in valid_values
            if target_state >= char.minValue
        }

    if char.maxValue is not None:
        valid_values = {
            target_state
            for target_state in valid_values
            if target_state <= char.maxValue
        }

    if char.valid_values:
        valid_values = valid_values.intersection(set(char.valid_values))

    return valid_values


def check_pin_format(pin: str) -> None:
    """
    Checks the format of the given pin: XXX-XX-XXX with X being a digit from 0 to 9

    :raises MalformedPinError: if the validation fails
    """
    if not re.match(r"^\d\d\d-\d\d-\d\d\d$", pin):
        raise MalformedPinError(
            "The pin must be of the following XXX-XX-XXX where X is a digit between 0 and 9."
        )


def pair_with_auth(ff: FeatureFlags) -> bool:
    if ff & FeatureFlags.SUPPORTS_APPLE_AUTHENTICATION_COPROCESSOR:
        return True

    if ff & FeatureFlags.SUPPORTS_SOFTWARE_AUTHENTICATION:
        return False

    # We don't know what kind of pairing this is, assume no auth
    return False


def domain_to_name(domain) -> str:
    """
    Given a Bonjour domain name, return a human readable name.

    Zealous Lizard's Tune Studio._music._tcp.local. -> Zealous Lizard's Tune Studio
    Fooo._hap._tcp.local. -> Fooo
    Baaar._hap._tcp.local. -> Baar
    """
    if "." not in domain:
        return domain

    return domain.split(".")[0]


def domain_supported(domain) -> bool:
    if domain.endswith("._hap._tcp.local.") and IP_TRANSPORT_SUPPORTED:
        return True
    if domain.endswith("._hap._udp.local.") and COAP_TRANSPORT_SUPPORTED:
        return True
    return False


def serialize_broadcast_key(broadcast_key: bytes | None) -> str | None:
    """Serialize a broadcast key to a string."""
    if broadcast_key is None:
        return None
    return broadcast_key.hex()


def deserialize_broadcast_key(broadcast_key: str | None) -> bytes | None:
    """Deserialize a broadcast key from a string."""
    if broadcast_key is None:
        return None
    return bytes.fromhex(broadcast_key)
