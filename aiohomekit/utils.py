import enum

from aiohomekit.model.characteristics import Characteristic

from .const import IP_TRANSPORT_SUPPORTED


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
    return False
