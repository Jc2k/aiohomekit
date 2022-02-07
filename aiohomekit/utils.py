import enum
import re

from aiohomekit.exceptions import MalformedPinError
from aiohomekit.model.characteristics import Characteristic
from aiohomekit.model.feature_flags import FeatureFlags


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
    return True
