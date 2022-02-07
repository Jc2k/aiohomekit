from __future__ import annotations

import logging
from typing import TYPE_CHECKING

from bleak import BleakScanner

if TYPE_CHECKING:
    from aiohomekit.controller import Controller

from .discovery import BleDiscovery

logger = logging.getLogger(__name__)


def parse_manufacturer_specific(input_data: bytes):
    """
    Parse the manufacturer specific data as returned via Bluez ManufacturerData. This skips the data for LEN, ADT and
    CoID as specified in Chapter 6.4.2.2 of the spec on page 124. Data therefore starts at TY (must be 0x06).
    :param input_data: manufacturer specific data as bytes
    :return: a dict containing the type (key 'type', value 'HomeKit'), the status flag (key 'sf'), human readable
             version of the status flag (key 'flags'), the device id (key 'device_id'), the accessory category
             identifier (key 'acid'), human readable version of the category (key 'category'), the global state number
             (key 'gsn'), the configuration number (key 'cn') and the compatible version (key 'cv')
    """
    logging.debug("manufacturer specific data: %s", input_data.hex())

    # the type must be 0x06 as defined on page 124 table 6-29
    ty = input_data[0]
    input_data = input_data[1:]
    if ty == 0x06:
        ty = "HomeKit"

        ail = input_data[0]
        logging.debug("advertising interval %s", f"{ail:02x}")
        length = ail & 0b00011111
        if length != 13:
            logging.debug("error with length of manufacturer data")
        input_data = input_data[1:]

        sf = input_data[0]
        flags = sf
        input_data = input_data[1:]

        device_id = (
            ":".join(input_data[:6].hex()[0 + i : 2 + i] for i in range(0, 12, 2))
        ).upper()
        input_data = input_data[6:]

        acid = int.from_bytes(input_data[:2], byteorder="little")
        input_data = input_data[2:]

        gsn = int.from_bytes(input_data[:2], byteorder="little")
        input_data = input_data[2:]

        cn = input_data[0]
        input_data = input_data[1:]

        cv = input_data[0]
        input_data = input_data[1:]
        if len(input_data) > 0:
            logging.debug("remaining data: %s", input_data.hex())
        return {
            "manufacturer": "apple",
            "type": ty,
            "sf": sf,
            "flags": flags,
            "id": device_id,
            "acid": acid,
            "s#": gsn,
            "c#": cn,
            "cv": cv,
            "ci": int(acid),
            "category": int(acid),
            "ff": 0,
            "md": "",
            "pv": 0,
            "statusflags": 0,
        }


class BleController:
    devices: dict[str, BleDiscovery]

    def __init__(self, controller: Controller):
        self.devices = {}

        self._controller = controller
        self._scanner = BleakScanner()

    def _device_detected(self, device, advertisement_data):
        if not (mfr_data := advertisement_data.manufacturer_data):
            return

        if not (apple_data := mfr_data.get(76)):
            return

        if apple_data[0] != 0x06:
            return

        data = parse_manufacturer_specific(apple_data)

        if data["id"] in self.devices:
            self.devices[data["id"]]._async_process_advertisement(data)
            return

        dev = self.devices[data["id"]] = BleDiscovery(self._controller, device, data)
        print(dev.address, dev.info["name"])

    async def __aenter__(self) -> BleController:
        self._scanner.register_detection_callback(self._device_detected)
        await self._scanner.start()
        return self

    async def __aexit__(self, *args):
        await self._scanner.stop()
        self._scanner.register_detection_callback(None)
