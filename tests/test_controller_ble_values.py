from aiohomekit.controller.ble.values import to_bytes
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
