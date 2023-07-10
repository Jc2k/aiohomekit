#
# Copyright 2019 aiohomekit team
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

from aiohomekit.enum import EnumWithDescription


class HapStatusCode(EnumWithDescription):
    SUCCESS = 0, "This specifies a success for the request."
    INSUFFICIENT_PRIVILEGES = -70401, "Request denied due to insufficient privileges."
    UNABLE_TO_COMMUNICATE = (
        -70402,
        "Unable to communicate with requested service, e.g. the power to the accessory was turned off.",
    )
    RESOURCE_BUSY = -70403, "Resource is busy, try again."
    CANT_WRITE_READ_ONLY = -70404, "Cannot write to read only characteristic."
    CANT_READ_WRITE_ONLY = -70405, "Cannot read from a write only characteristic."
    NOTIFICATION_NOT_SUPPORTED = (
        -70406,
        "Notification is not supported for characteristic.",
    )
    OUT_OF_RESOURCES = -70407, "Out of resources to process request."
    TIMED_OUT = -70408, "Operation timed out."
    RESOURCE_NOT_EXIST = -70409, "Resource does not exist."
    INVALID_VALUE = -70410, "Accessory received an invalid value in a write request."
    INSUFFICIENT_AUTH = -70411, "Insufficient Authorization."
    NOT_ALLOWED_IN_CURRENT_STATE = -70412, "Not allowed in current state"


def to_status_code(status_code: int) -> HapStatusCode:
    # Some HAP implementations return positive values for error code (myq)
    status_code = abs(status_code) * -1
    return HapStatusCode(status_code)


class _HapBleStatusCodes:
    """
    This data is taken from Table 6-26 HAP Status Codes on page 116.
    """

    SUCCESS = 0x00
    UNSUPPORTED_PDU = 0x01
    MAX_PROCEDURES = 0x02
    INSUFFICIENT_AUTHORIZATION = 0x03
    INVALID_INSTANCE_ID = 0x04
    INSUFFICIENT_AUTHENTICATION = 0x05
    INVALID_REQUEST = 0x06

    def __init__(self) -> None:
        self._codes = {
            _HapBleStatusCodes.SUCCESS: "The request was successful.",
            _HapBleStatusCodes.UNSUPPORTED_PDU: "The request failed as the HAP PDU was not recognized or supported.",
            _HapBleStatusCodes.MAX_PROCEDURES: "The request failed as the accessory has reached the limit on"
            " the simultaneous procedures it can handle.",
            _HapBleStatusCodes.INSUFFICIENT_AUTHORIZATION: "Characteristic requires additional authorization data.",
            _HapBleStatusCodes.INVALID_INSTANCE_ID: "The HAP Request's characteristic Instance Id did not match"
            " the addressed characteristic's instance Id",
            _HapBleStatusCodes.INSUFFICIENT_AUTHENTICATION: "Characterisitc access required a secure session to be"
            " established.",
            _HapBleStatusCodes.INVALID_REQUEST: "Accessory was not able to perform the requested operation",
        }

        self._categories_rev = {self._codes[k]: k for k in self._codes.keys()}

    def __getitem__(self, item):
        if item in self._codes:
            return self._codes[item]

        raise KeyError(f"Item {item} not found")


HapBleStatusCodes = _HapBleStatusCodes()
