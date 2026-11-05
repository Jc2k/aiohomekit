from aiohomekit.controller.ble.values import from_bytes, to_bytes
from aiohomekit.model import Accessory
from aiohomekit.model.characteristics import (
    CharacteristicFormats,
    CharacteristicPermissions,
    CharacteristicsTypes,
)
from aiohomekit.model.services import ServicesTypes


def _data_char():
    accessory = Accessory(1)
    service = accessory.add_service(ServicesTypes.LEAK_SENSOR)
    return service.add_char(
        CharacteristicsTypes.VENDOR_EVE_CONFIG_WRITE,
        perms=[CharacteristicPermissions.paired_write],
        format=CharacteristicFormats.data,
    )


def test_data_to_bytes_accepts_raw_bytes():
    assert to_bytes(_data_char(), b"\x4e\x01\x01") == b"\x4e\x01\x01"


def test_data_to_bytes_accepts_hex_string():
    # Reads of data characteristics return hex, so writes accept it too.
    assert to_bytes(_data_char(), "4e0101") == b"\x4e\x01\x01"


def test_data_round_trip():
    char = _data_char()
    assert to_bytes(char, from_bytes(char, b"\x4e\x01\x01")) == b"\x4e\x01\x01"
