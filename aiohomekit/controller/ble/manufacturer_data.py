from __future__ import annotations

from dataclasses import dataclass
import struct

from bleak.backends.device import BLEDevice
from bleak.backends.scanner import AdvertisementData

from aiohomekit.controller.abstract import AbstractDescription
from aiohomekit.model.categories import Categories
from aiohomekit.model.status_flags import StatusFlags

UNPACK_HHBB = struct.Struct("<HHBB").unpack
UNPACK_HH = struct.Struct("<HH").unpack

APPLE_MANUFACTURER_ID = 76
HOMEKIT_ADVERTISEMENT_TYPE = 0x06
HOMEKIT_ENCRYPTED_NOTIFICATION_TYPE = 0x11


@dataclass
class HomeKitAdvertisement(AbstractDescription):

    setup_hash: bytes
    address: str
    state_num: int

    @classmethod
    def from_manufacturer_data(
        cls, name: str, address: str, manufacturer_data: dict[int, bytes]
    ) -> HomeKitAdvertisement:
        if not (data := manufacturer_data.get(APPLE_MANUFACTURER_ID)):
            raise ValueError("Not an Apple device")

        if data[0] != HOMEKIT_ADVERTISEMENT_TYPE:
            raise ValueError("Not a HomeKit device")

        sf = data[6]
        device_id = ":".join(
            data[3:9].hex()[0 + i : 2 + i] for i in range(0, 12, 2)
        ).lower()
        acid, gsn, cn, cv = UNPACK_HHBB(data[9:15])
        sh = data[15:19]

        return cls(
            name=name,
            id=device_id,
            category=Categories(acid),
            status_flags=StatusFlags(sf),
            config_num=cn,
            state_num=gsn,
            setup_hash=sh,
            address=address,
        )

    @classmethod
    def from_advertisement(
        cls, device: BLEDevice, advertisement_data: AdvertisementData
    ) -> HomeKitAdvertisement:
        if not (mfr_data := advertisement_data.manufacturer_data):
            raise ValueError("No manufacturer data")

        return cls.from_manufacturer_data(device.name, device.address, mfr_data)


@dataclass
class HomeKitEncryptedNotification:

    name: str
    address: str
    id: str
    state_num: int
    iid: int
    value: bytes
    auth_tag: bytes

    @classmethod
    def from_manufacturer_data(
        cls, name, address, manufacturer_data
    ) -> HomeKitAdvertisement:
        if not (data := manufacturer_data.get(APPLE_MANUFACTURER_ID)):
            raise ValueError("Not an Apple device")

        if data[0] != HOMEKIT_ENCRYPTED_NOTIFICATION_TYPE:
            raise ValueError("Not a HomeKit encrypted notification")

        device_id = ":".join(
            data[2:8].hex()[0 + i : 2 + i] for i in range(0, 12, 2)
        ).lower()
        gsn, iid = UNPACK_HH(data[8:12])
        value = data[12:20]
        auth_tag = data[20:24]

        return cls(
            name=name,
            id=device_id,
            state_num=gsn,
            address=address,
            iid=iid,
            value=value,
            auth_tag=auth_tag,
        )

    @classmethod
    def from_advertisement(
        cls, device: BLEDevice, advertisement_data: AdvertisementData
    ) -> HomeKitAdvertisement:
        if not (mfr_data := advertisement_data.manufacturer_data):
            raise ValueError("No manufacturer data")

        return cls.from_manufacturer_data(device.name, device.address, mfr_data)
