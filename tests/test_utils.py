from aiohomekit.model.characteristics import RemoteKeyValues
from aiohomekit.utils import clamp_enum_to_char


def test_clamp_enum_valid_vals():
    valid_vals = clamp_enum_to_char(
        RemoteKeyValues, {"valid-values": [RemoteKeyValues.PLAY_PAUSE]}
    )
    assert valid_vals == {RemoteKeyValues.PLAY_PAUSE}


def test_clamp_enum_min_max():
    valid_vals = clamp_enum_to_char(
        RemoteKeyValues,
        {
            "minValue": RemoteKeyValues.PLAY_PAUSE,
            "maxValue": RemoteKeyValues.PLAY_PAUSE,
        },
    )
    assert valid_vals == {RemoteKeyValues.PLAY_PAUSE}
