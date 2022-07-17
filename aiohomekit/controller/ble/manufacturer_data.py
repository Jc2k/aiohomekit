from __future__ import annotations

from dataclasses import dataclass
import struct

from aiohomekit.controller.abstract import AbstractDescription
from aiohomekit.model.categories import Categories
from aiohomekit.model.status_flags import StatusFlags


@dataclass
class HomeKitAdvertisement(AbstractDescription):

    setup_hash: bytes
    address: str
    state_num: int

    @classmethod
    def from_manufacturer_data(
        cls, name, address, manufacturer_data
    ) -> HomeKitAdvertisement:
        if not (data := manufacturer_data.get(76)):
            raise ValueError("Not an Apple device")

        if data[0] != 0x06:
            raise ValueError("Not a HomeKit device")

        type, stl, sf = struct.unpack("<BBB", data[:3])
        device_id = ":".join(
            data[3:9].hex()[0 + i : 2 + i] for i in range(0, 12, 2)
        ).lower()
        acid, gsn, cn, cv = struct.unpack("<HHBB", data[9:15])
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
    def from_advertisement(cls, device, advertisement_data) -> HomeKitAdvertisement:
        if not (mfr_data := advertisement_data.manufacturer_data):
            raise ValueError("No manufacturer data")

        return cls.from_manufacturer_data(device.name, device.address, mfr_data)
