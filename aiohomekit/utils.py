import enum

from aiohomekit.model.characteristics import Characteristic


def clamp_enum_to_char(all_valid_values: enum.IntEnum, char: Characteristic):
    """Clamp possible values of an enum to restrictions imposed by a manufacturer."""
    valid_values = set(all_valid_values)

    if char.minValue:
        valid_values = {
            target_state
            for target_state in valid_values
            if target_state >= char.minValue
        }

    if char.maxValue:
        valid_values = {
            target_state
            for target_state in valid_values
            if target_state <= char.maxValue
        }

    if char.valid_values:
        valid_values = valid_values.intersection(set(char.valid_values))

    return valid_values
