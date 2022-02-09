from __future__ import annotations

from dataclasses import dataclass
import struct

from aiohomekit.model.categories import Categories
from aiohomekit.model.status_flags import StatusFlags


@dataclass
class ManufacturerData:

    device_id: str
    category: Categories
    status_flags: StatusFlags
    config_num: int
    state_num: int
    setup_hash: bytes

    @classmethod
    def from_bytes(cls, data: bytes) -> ManufacturerData:
        type, stl, sf = struct.unpack("<BBB", data[:3])
        device_id = ":".join(
            data[3:9].hex()[0 + i : 2 + i] for i in range(0, 12, 2)
        ).upper()
        acid, gsn, cn, cv = struct.unpack("<HHBB", data[9:15])
        sh = data[15:19]

        return ManufacturerData(
            device_id=device_id,
            category=Categories(acid),
            status_flags=StatusFlags(sf),
            config_num=cn,
            state_num=gsn,
            setup_hash=sh,
        )
