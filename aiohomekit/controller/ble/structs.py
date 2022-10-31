#
# Copyright 2022 aiohomekit team
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
from collections.abc import Sequence
from dataclasses import dataclass, field
import enum
import struct
from typing import Any, Optional, Union

from aiohomekit.tlv8 import TLVStruct, tlv_entry, u8, u16, u128

from .const import AdditionalParameterTypes


@dataclass
class ProtocolParams:

    state_number: int
    config_number: int
    advertising_id: bytes
    broadcast_key: Optional[bytes]


class ProtocolParamsTLV(enum.IntEnum):
    """Protocol params."""

    GlobalStateNumber = 0x01
    ConfigurationNumber = 0x02
    AdvertisingId = 0x03
    BroadcastKey = 0x04


class HAP_BLE_PROTOCOL_CONFIGURATION_REQUEST_TLV(enum.IntEnum):
    GenerateBroadcastEncryptionKey = 0x01
    GetAllParams = 0x02


class HAP_BLE_CHARACTERISTIC_CONFIGURATION_REQUEST_TLV(enum.IntEnum):
    kTLVHAPParamCharacteristicConfigurationProperties = 0x01
    kTLVHAPParamCharacteristicConfigurationBroadcastInterval = 0x02


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


@dataclass
class BleRequest(TLVStruct):
    expect_response: u8 = tlv_entry(AdditionalParameterTypes.ParamReturnResponse)
    value: bytes = tlv_entry(AdditionalParameterTypes.Value)


DATA_TYPE_STR = {
    0x01: "bool",
    0x04: "uint8",
    0x06: "uint16",
    0x08: "uint32",
    0x0A: "uint64",
    0x10: "int",
    0x14: "float",
    0x19: "string",
    0x1B: "data",
}


@dataclass
class Characteristic(TLVStruct):
    # raw value
    _value: bytes = field(init=False, default=None)

    type: u128 = tlv_entry(HAP_TLV.kTLVHAPParamCharacteristicType)
    instance_id: u16 = tlv_entry(HAP_TLV.kTLVHAPParamCharacteristicInstanceId)
    # permission bits
    properties: u16 = tlv_entry(
        HAP_TLV.kTLVHAPParamHAPCharacteristicPropertiesDescriptor
    )
    # 7 bytes, contains type & unit
    presentation_format: bytes = tlv_entry(
        HAP_TLV.kTLVHAPParamGATTPresentationFormatDescriptor
    )
    # min/max, int or float, same type as value
    valid_range: bytes = tlv_entry(HAP_TLV.kTLVHAPParamGATTValidRange)
    # int or float, same type as value
    step_value: bytes = tlv_entry(HAP_TLV.kTLVHAPParamHAPStepValueDescriptor)
    # list of valid uint8 values
    valid_values: bytes = tlv_entry(HAP_TLV.kTLVHAPParamHAPValidValuesDescriptor)
    # list of valid (start, end) uint8 range values
    valid_values_range: bytes = tlv_entry(
        HAP_TLV.kTLVHAPParamHAPValidValuesRangeDescriptor
    )
    service_instance_id: bytes = tlv_entry(HAP_TLV.kTLVHAPParamServiceInstanceId)
    service_type: bytes = tlv_entry(HAP_TLV.kTLVHAPParamServiceType)
    user_description: bytes = tlv_entry(
        HAP_TLV.kTLVHAPParamGATTUserDescriptionDescriptor
    )

    @property
    def supports_read(self) -> bool:
        return self.properties & 0x0001

    @property
    def supports_write(self) -> bool:
        return self.properties & 0x0002

    @property
    def supports_additional_authorization_data(self) -> bool:
        return self.properties & 0x0004

    @property
    def requires_hap_characteristic_timed_write_procedure(self) -> bool:
        return self.properties & 0x0008

    @property
    def supports_secure_reads(self) -> bool:
        return self.properties & 0x0010

    @property
    def supports_secure_writes(self) -> bool:
        return self.properties & 0x0020

    @property
    def hidden_from_user(self) -> bool:
        return self.properties & 0x0040

    @property
    def notifies_events_in_connected_state(self) -> bool:
        return self.properties & 0x0080

    @property
    def notifies_events_in_disconnected_state(self) -> bool:
        return self.properties & 0x0100

    @property
    def supports_broadcast_notify(self) -> bool:
        return self.properties & 0x0200

    @property
    def pf_format(self):
        if self.presentation_format is None:
            return None
        return struct.unpack("<BxHxxx", self.presentation_format)[0]

    @property
    def data_type_str(self):
        return DATA_TYPE_STR.get(self.pf_format, "unknown")

    @property
    def pf_unit(self):
        if self.presentation_format is None:
            return None
        return struct.unpack("<BxHxxx", self.presentation_format)[1]

    @property
    def data_unit_str(self):
        if self.pf_unit == 0x272F:
            return "celsius"
        elif self.pf_unit == 0x2763:
            return "arcdegrees"
        elif self.pf_unit == 0x27AD:
            return "percentage"
        elif self.pf_unit == 0x2700:
            return "unitless"
        elif self.pf_unit == 0x2731:
            return "lux"
        elif self.pf_unit == 0x2703:
            return "seconds"
        return "unknown"

    @property
    def raw_value(self):
        return self._value

    @raw_value.setter
    def raw_value(self, value):
        self._value = value

    @property
    def value(self):
        return self._unpack_value(self._value)

    def _unpack_value(self, value: bytes) -> Any:
        if not self.pf_format:
            return value
        if self.pf_format == 0x01:
            val = struct.unpack("<B", value)[0]
            return bool(val)
        if self.pf_format == 0x04:
            return struct.unpack("<B", value)[0]
        if self.pf_format == 0x06:
            return struct.unpack("<H", value)[0]
        if self.pf_format == 0x08:
            return struct.unpack("<L", value)[0]
        if self.pf_format == 0x0A:
            return struct.unpack("<Q", value)[0]
        if self.pf_format == 0x10:
            return struct.unpack("<l", value)[0]
        if self.pf_format == 0x14:
            return struct.unpack("<f", value)[0]
        if self.pf_format == 0x19:
            return bytes.decode(value)
        if self.pf_format == 0x1B:
            # ???
            return value.hex()
        return value

    @value.setter
    def value(self, value):
        self._value = self._pack_value(value)

    def _pack_value(self, value: Any) -> bytes:
        # if data type is unknown, copy value without modification
        if not self.pf_format:
            return value
        if self.pf_format == 0x01:
            return b"\x01" if value else b"\x00"
        if self.pf_format == 0x04:
            return struct.pack("<B", value)
        if self.pf_format == 0x06:
            return struct.pack("<H", value)
        if self.pf_format == 0x08:
            return struct.pack("<L", value)
        if self.pf_format == 0x0A:
            return struct.pack("<Q", value)
        if self.pf_format == 0x10:
            return struct.pack("<l", value)
        if self.pf_format == 0x14:
            return struct.pack("<f", value)
        if self.pf_format == 0x19:
            return value.encode()
        if self.pf_format == 0x1B:
            # ???
            return bytes.fromhex(value)
        return value

    @property
    def min_step(self) -> Any:
        if not self.step_value:
            return None
        return self._unpack_value(self.step_value)

    @property
    def min_max_value(self) -> Optional[tuple[Union[int, float], Union[int, float]]]:
        if not self.valid_range:
            return None
        if self.pf_format == 0x04:
            return struct.unpack("<BB", self.valid_range)
        if self.pf_format == 0x06:
            return struct.unpack("<HH", self.valid_range)
        if self.pf_format == 0x08:
            return struct.unpack("<LL", self.valid_range)
        if self.pf_format == 0x0A:
            return struct.unpack("<QQ", self.valid_range)
        if self.pf_format == 0x10:
            return struct.unpack("<ll", self.valid_range)
        if self.pf_format == 0x14:
            return struct.unpack("<ff", self.valid_range)
        return None

    def to_dict(self):
        perms = list()
        if self.supports_secure_reads:
            perms.append("pr")
        if self.supports_secure_writes:
            perms.append("pw")
        if self.notifies_events_in_connected_state:
            perms.append("ev")
        if self.supports_additional_authorization_data:
            perms.append("aa")
        if self.requires_hap_characteristic_timed_write_procedure:
            perms.append("tw")
        if self.hidden_from_user:
            perms.append("hd")

        result = {
            "type": f"{self.type:X}",
            "iid": self.instance_id,
            "perms": perms,
        }

        if self.supports_broadcast_notify:
            result["broadcast_events"] = True

        if self.notifies_events_in_disconnected_state:
            result["disconnected_events"] = True

        if self.data_type_str != "unknown":
            result["format"] = self.data_type_str

        if self.data_unit_str not in ("unknown", "unitless"):
            result["unit"] = self.data_unit_str

        if self._value is not None:
            result["value"] = self.value

        if self.min_step:
            result["minStep"] = self.min_step

        if self.min_max_value:
            min_max_value = self.min_max_value
            result["minValue"] = min_max_value[0]
            result["maxValue"] = min_max_value[1]

        return result


@dataclass
class Service(TLVStruct):
    # permission bits
    service_properties: u16 = tlv_entry(HAP_TLV.kTLVHAPParamHAPServiceProperties)
    linked_services: Sequence[u16] = tlv_entry(HAP_TLV.kTLVHAPParamHAPLinkedServices)

    @property
    def primary_service(self) -> bool:
        return self.service_properties and self.service_properties & 0x0001

    @property
    def hidden_service(self) -> bool:
        return self.service_properties and self.service_properties & 0x0002

    @property
    def supports_configuration(self) -> bool:
        return self.service_properties and self.service_properties & 0x0004

    def to_dict(self):
        perms = list()
        if self.hidden_service:
            perms.append("hd")

        result = {
            "perms": perms,
        }

        if self.linked_services:
            result["linked"] = self.linked_services

        return result
