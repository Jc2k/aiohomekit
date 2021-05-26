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

import enum


class HapStatusCode(enum.Enum):

    SUCCESS = 0
    INSUFFICIENT_PRIVILEGES = -70401
    UNABLE_TO_COMMUNICATE = -70402
    RESOURCE_BUSY = -70403
    CANT_WRITE_READ_ONLY = -70404
    CANT_READ_WRITE_ONLY = -70405
    NOTIFICATION_NOT_SUPPORTED = -70406
    OUT_OF_RESOURCES = -70407
    TIMED_OUT = -70408
    RESOURCE_NOT_EXIST = -70409
    INVALID_VALUE = -70410
    INSUFFICIENT_AUTH = -70411


HAP_STATUS_CODE_DESCRIPTIONS = {
    HapStatusCode.SUCCESS: "This specifies a success for the request.",
    HapStatusCode.INSUFFICIENT_PRIVILEGES: "Request denied due to insufficient privileges.",
    HapStatusCode.UNABLE_TO_COMMUNICATE: "Unable to communicate with requested service, e.g. the power to the accessory was turned off.",
    HapStatusCode.RESOURCE_BUSY: "Resource is busy, try again.",
    HapStatusCode.CANT_WRITE_READ_ONLY: "Cannot write to read only characteristic.",
    HapStatusCode.CANT_READ_WRITE_ONLY: "Cannot read from a write only characteristic.",
    HapStatusCode.NOTIFICATION_NOT_SUPPORTED: "Notification is not supported for characteristic.",
    HapStatusCode.OUT_OF_RESOURCES: "Out of resources to process request.",
    HapStatusCode.TIMED_OUT: "Operation timed out.",
    HapStatusCode.RESOURCE_NOT_EXIST: "Resource does not exist.",
    HapStatusCode.INVALID_VALUE: "Accessory received an invalid value in a write request.",
    HapStatusCode.INSUFFICIENT_AUTH: "Insufficient Authorization.",
}


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
