from aiohomekit.model import Accessory
from aiohomekit.model.characteristics import (
    CharacteristicsTypes,
    InputEventValues,
    RemoteKeyValues,
)
from aiohomekit.model.services import ServicesTypes
from aiohomekit.utils import clamp_enum_to_char


def test_clamp_enum_valid_vals():
    a = Accessory()
    tv_service = a.add_service(service_type=ServicesTypes.TELEVISION)
    char = tv_service.add_char(
        CharacteristicsTypes.REMOTE_KEY,
        valid_values=[RemoteKeyValues.PLAY_PAUSE],
        min_value=None,
        max_value=None,
    )

    valid_vals = clamp_enum_to_char(RemoteKeyValues, char)
    assert valid_vals == {RemoteKeyValues.PLAY_PAUSE}


def test_clamp_enum_min_max():
    a = Accessory()
    tv_service = a.add_service(service_type=ServicesTypes.TELEVISION)
    char = tv_service.add_char(
        CharacteristicsTypes.REMOTE_KEY,
        valid_values=None,
        min_value=RemoteKeyValues.PLAY_PAUSE,
        max_value=RemoteKeyValues.PLAY_PAUSE,
    )

    valid_vals = clamp_enum_to_char(RemoteKeyValues, char)

    assert valid_vals == {RemoteKeyValues.PLAY_PAUSE}


def test_clamp_enum_min_max_single_press():
    a = Accessory()
    tv_service = a.add_service(service_type=ServicesTypes.STATELESS_PROGRAMMABLE_SWITCH)
    char = tv_service.add_char(
        CharacteristicsTypes.INPUT_EVENT,
        valid_values=None,
        min_value=InputEventValues.SINGLE_PRESS,
        max_value=InputEventValues.SINGLE_PRESS,
    )

    valid_vals = clamp_enum_to_char(InputEventValues, char)

    assert valid_vals == {InputEventValues.SINGLE_PRESS}


def test_clamp_enum_min_max_unclamped_button_press():
    a = Accessory()
    tv_service = a.add_service(service_type=ServicesTypes.STATELESS_PROGRAMMABLE_SWITCH)
    char = tv_service.add_char(
        CharacteristicsTypes.INPUT_EVENT,
    )

    valid_vals = clamp_enum_to_char(InputEventValues, char)

    assert valid_vals == {
        InputEventValues.SINGLE_PRESS,
        InputEventValues.DOUBLE_PRESS,
        InputEventValues.LONG_PRESS,
    }
