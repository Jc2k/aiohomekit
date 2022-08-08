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
from __future__ import annotations

import enum
import logging
from typing import Any

logger = logging.getLogger(__name__)


class HAP_TLV(enum.IntEnum):
    # Additional Parameter Types for BLE (Table 6-9 page 98)
    kTLVHAPSeparator = 0x00
    kTLVHAPParamValue = 0x01
    kTLVHAPParamAdditionalAuthorizationData = 0x02
    kTLVHAPParamOrigin = 0x03
    kTLVHAPParamCharacteristicType = 0x04
    kTLVHAPParamCharacteristicInstanceId = 0x05
    kTLVHAPParamServiceType = 0x06
    kTLVHAPParamServiceInstanceId = 0x07
    kTLVHAPParamTTL = 0x08
    kTLVHAPParamParamReturnResponse = 0x09
    kTLVHAPParamHAPCharacteristicPropertiesDescriptor = 0x0A
    kTLVHAPParamGATTUserDescriptionDescriptor = 0x0B
    kTLVHAPParamGATTPresentationFormatDescriptor = 0x0C
    kTLVHAPParamGATTValidRange = 0x0D
    kTLVHAPParamHAPStepValueDescriptor = 0x0E
    kTLVHAPParamHAPServiceProperties = 0x0F
    kTLVHAPParamHAPLinkedServices = 0x10
    kTLVHAPParamHAPValidValuesDescriptor = 0x11
    kTLVHAPParamHAPValidValuesRangeDescriptor = 0x12
    kTLVHAPParamUnknown_13_Characteristic = 0x13
    kTLVHAPParamUnknown_14_Characteristics = 0x14
    kTLVHAPParamUnknown_15_Service = 0x15
    kTLVHAPParamUnknown_16_Services = 0x16
    kTLVHAPParamUnknown_17 = 0x17
    kTLVHAPParamUnknown_18 = 0x18
    kTLVHAPParamUnknown_19 = 0x19
    kTLVHAPParamUnknown_1A_AccessoryInstanceId = 0x1A


K_TLV_TYPE_NAMES = {
    0: "Method",
    1: "Identifier",
    2: "Salt",
    3: "PublicKey",
    4: "Proof",
    5: "EncryptedData",
    6: "State",
    7: "Error",
    8: "RetryDelay",
    9: "Certificate",
    10: "Signature",
    11: "Permissions",
    12: "FragmentData",
    13: "FragmentLast",
    14: "SessionID",
    255: "Separator",
}

UNKNOWN_TLV_TYPE_NAME = "Unknown"


K_TLV_ERROR_NAMES = {
    1: "Unknown",
    2: "Authentication",
    3: "Backoff",
    4: "MaxPeers",
    5: "MaxTries",
    6: "Unavailable",
    7: "Busy",
}

UNKNOWN_TLV_ERROR_NAME = "Unknown"


class TLV:
    """
    as described in Appendix 12 (page 251)
    """

    # Steps
    M1 = bytearray(b"\x01")
    M2 = bytearray(b"\x02")
    M3 = bytearray(b"\x03")
    M4 = bytearray(b"\x04")
    M5 = bytearray(b"\x05")
    M6 = bytearray(b"\x06")

    # Methods (see table 4-4 page 60)
    PairSetup = bytearray(b"\x00")
    PairSetupWithAuth = bytearray(b"\x01")
    PairVerify = bytearray(b"\x02")
    AddPairing = bytearray(b"\x03")
    RemovePairing = bytearray(b"\x04")
    ListPairings = bytearray(b"\x05")

    # TLV Values (see table 4-6 page 61)
    kTLVType_Method = 0
    kTLVType_Identifier = 1
    kTLVType_Salt = 2
    kTLVType_PublicKey = 3
    kTLVType_Proof = 4
    kTLVType_EncryptedData = 5
    kTLVType_State = 6
    kTLVType_Error = 7
    kTLVType_RetryDelay = 8
    kTLVType_Certificate = 9
    kTLVType_Signature = 10
    kTLVType_Permissions = 11  # 0x00 => reg. user, 0x01 => admin
    kTLVType_Permission_RegularUser = bytearray(b"\x00")
    kTLVType_Permission_AdminUser = bytearray(b"\x01")
    kTLVType_FragmentData = 12
    kTLVType_FragmentLast = 13
    kTLVType_Separator = 255
    kTLVType_Separator_Pair = [255, bytearray(b"")]
    kTLVType_SessionID = 0x0E  # Table 6-27 page 116

    # Errors (see table 4-5 page 60)
    kTLVError_Unknown = bytearray(b"\x01")
    kTLVError_Authentication = bytearray(b"\x02")
    kTLVError_Backoff = bytearray(b"\x03")
    kTLVError_MaxPeers = bytearray(b"\x04")
    kTLVError_MaxTries = bytearray(b"\x05")
    kTLVError_Unavailable = bytearray(b"\x06")
    kTLVError_Busy = bytearray(b"\x07")

    # Table 6-27 page 116
    kTLVMethod_Resume = 0x06

    kTLVHAPParamValue = 0x01
    kTLVHAPParamParamReturnResponse = 0x09

    @staticmethod
    def decode_bytes(bs: bytearray | bytes, expected: list[int] | None = None) -> list:
        return TLV.decode_bytearray(bytearray(bs), expected)

    @staticmethod
    def decode_bytearray(ba: bytearray, expected: list[int] | None = None) -> list:
        result = []
        # do not influence caller!
        tail = ba.copy()
        while len(tail) > 0:
            key = tail.pop(0)
            if expected and key not in expected:
                break
            length = tail.pop(0)
            value = tail[:length]
            if length != len(value):
                raise TlvParseException(
                    "Not enough data for length {} while decoding '{}'".format(
                        length, ba
                    )
                )
            tail = tail[length:]

            if len(result) > 0 and result[-1][0] == key:
                result[-1][1] += value
            else:
                result.append([key, value])
        logger.debug("receiving %s", TLV.to_string(result))
        return result

    @staticmethod
    def validate_key(k: int) -> bool:
        try:
            val = int(k)
            if val < 0 or val > 255:
                valid = False
            else:
                valid = True
        except ValueError:
            valid = False
        return valid

    @staticmethod
    def encode_list(d: list) -> bytearray:
        logger.debug("sending %s", TLV.to_string(d))
        result = bytearray()
        for key, value in d:
            if not TLV.validate_key(key):
                raise ValueError("Invalid key")

            # handle separators properly
            if key == TLV.kTLVType_Separator:
                if len(value) == 0:
                    result.append(key)
                    result.append(0)
                else:
                    raise ValueError("Separator must not have data")

            while len(value) > 0:
                result.append(key)
                if len(value) > 255:
                    length = 255
                    result.append(length)
                    for b in value[:length]:
                        result.append(b)
                    value = value[length:]
                else:
                    length = len(value)
                    result.append(length)
                    for b in value[:length]:
                        result.append(b)
                    value = value[length:]
        return result

    @staticmethod
    def to_string(d: Any) -> str:
        def entry_to_string(entry_key, entry_value) -> str:
            tlv_key = entry_key if isinstance(entry_key, int) else entry_key[0]
            name = K_TLV_TYPE_NAMES.get(tlv_key, UNKNOWN_TLV_TYPE_NAME)
            value_description = ""
            if tlv_key == TLV.kTLVType_Error:
                value_description = K_TLV_ERROR_NAMES.get(
                    entry_value[0], UNKNOWN_TLV_ERROR_NAME
                )
            if value_description:
                value_description = f" [{value_description}]"
            if isinstance(entry_value, bytearray):
                return "  {k} ({key_name}): ({len} bytes/{t}) 0x{v}{value_description}\n".format(
                    k=entry_key,
                    key_name=name,
                    v=entry_value.hex(),
                    len=len(entry_value),
                    t=type(entry_value),
                    value_description=value_description,
                )
            return (
                "  {k} ({key_name}): ({len} bytes/{t}) {v}{value_description}\n".format(
                    k=entry_key,
                    key_name=name,
                    v=entry_value,
                    len=len(entry_value),
                    t=type(entry_value),
                    value_description=value_description,
                )
            )

        if isinstance(d, dict):
            res = "{\n"
            for k in d.keys():
                res += entry_to_string(k, d[k])
            res += "}\n"
        else:
            res = "[\n"
            for k in d:
                res += entry_to_string(k[0], k[1])
            res += "]\n"
        return res


class TlvParseException(Exception):
    """Raised upon parse error with some TLV"""

    pass
