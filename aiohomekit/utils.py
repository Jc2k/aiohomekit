import enum


def clamp_enum_to_char(all_valid_values: enum.IntEnum, char):
    """Clamp possible values of an enum to restrictions imposed by a manufacturer."""
    valid_values = set(all_valid_values)

    if "minValue" in char:
        valid_values = {
            target_state
            for target_state in valid_values
            if target_state >= char["minValue"]
        }

    if "maxValue" in char:
        valid_values = {
            target_state
            for target_state in valid_values
            if target_state <= char["maxValue"]
        }

    if "valid-values" in char:
        valid_values = valid_values.intersection(set(char["valid-values"]))

    return valid_values
