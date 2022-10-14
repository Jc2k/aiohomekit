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
import struct
from typing import Any, Optional, Union

from aiohomekit.protocol.tlv import HAP_TLV
from aiohomekit.tlv8 import TLVStruct, tlv_entry, u16, u128


@dataclass
class Pdu09Characteristic(TLVStruct):
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

    user_descriptor: bytes = tlv_entry(
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
        if self.pf_format == 0x01:
            return "bool"
        elif self.pf_format in [0x04, 0x06, 0x08, 0x0A, 0x10]:
            return "int"
        elif self.pf_format == 0x14:
            return "float"
        elif self.pf_format == 0x19:
            return "string"
        elif self.pf_format == 0x1B:
            return "data"
        return "unknown"

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
        if not self._value:
            return None
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
class Pdu09CharacteristicContainer(TLVStruct):
    characteristic: Pdu09Characteristic = tlv_entry(
        HAP_TLV.kTLVHAPParamUnknown_13_Characteristic
    )


@dataclass
class Pdu09Service(TLVStruct):
    type: u128 = tlv_entry(HAP_TLV.kTLVHAPParamServiceType)
    instance_id: u16 = tlv_entry(HAP_TLV.kTLVHAPParamServiceInstanceId)
    _characteristics: Sequence[Pdu09CharacteristicContainer] = tlv_entry(
        HAP_TLV.kTLVHAPParamUnknown_14_Characteristics
    )
    properties: u16 = tlv_entry(HAP_TLV.kTLVHAPParamHAPServiceProperties)
    linked_services: Sequence[u16] = tlv_entry(HAP_TLV.kTLVHAPParamHAPLinkedServices)

    @property
    def characteristics(self) -> list[Pdu09Characteristic]:
        return [container.characteristic for container in self._characteristics]

    def find_characteristic_by_iid(self, iid):
        for characteristic in self.characteristics:
            if characteristic.instance_id == iid:
                return characteristic
        return None

    def find_characteristic_by_type(self, characteristic_type):
        for characteristic in self.characteristics:
            if characteristic.type == characteristic_type:
                return characteristic
        return None

    def to_dict(self):
        res = {
            "type": f"{self.type:X}",
            "iid": self.instance_id,
            "characteristics": [
                characteristic.to_dict() for characteristic in self.characteristics
            ],
        }

        if self.linked_services:
            res["linked"] = self.linked_services

        return res


@dataclass
class Pdu09ServiceContainer(TLVStruct):
    service: Pdu09Service = tlv_entry(HAP_TLV.kTLVHAPParamUnknown_15_Service)


@dataclass
class Pdu09Accessory(TLVStruct):
    instance_id: u16 = tlv_entry(HAP_TLV.kTLVHAPParamUnknown_1A_AccessoryInstanceId)
    _services: Sequence[Pdu09ServiceContainer] = tlv_entry(
        HAP_TLV.kTLVHAPParamUnknown_16_Services
    )

    @property
    def services(self) -> list[Pdu09Service]:
        return [container.service for container in self._services]

    def find_characteristic_by_iid(self, iid):
        for service in self.services:
            characteristic = service.find_characteristic_by_iid(iid)
            if characteristic:
                return characteristic
        return None

    def find_service_by_type(self, service_type):
        for service in self.services:
            if service.type == service_type:
                return service
        return None

    def find_service_characteristic_by_type(self, service_type, characteristic_type):
        service = self.find_service_by_type(service_type)
        if service:
            return service.find_characteristic_by_type(characteristic_type)
        return None

    def to_dict(self):
        return {
            "aid": self.instance_id,
            "services": [service.to_dict() for service in self.services],
        }


@dataclass
class Pdu09AccessoryContainer(TLVStruct):
    accessory: Pdu09Accessory = tlv_entry(HAP_TLV.kTLVHAPParamUnknown_19)


@dataclass
class Pdu09Database(TLVStruct):
    _accessories: Sequence[Pdu09AccessoryContainer] = tlv_entry(
        HAP_TLV.kTLVHAPParamUnknown_18
    )

    @property
    def accessories(self) -> list[Pdu09Accessory]:
        return [container.accessory for container in self._accessories]

    def find_characteristic_by_aid_iid(self, aid, iid):
        for accessory in self.accessories:
            if accessory.instance_id == aid:
                return accessory.find_characteristic_by_iid(iid)
        return None

    # return first matching iid
    def find_characteristic_by_iid(self, iid):
        for accessory in self.accessories:
            characteristic = accessory.find_characteristic_by_iid(iid)
            if characteristic:
                return characteristic
        return None

    def to_dict(self):
        return [accessory.to_dict() for accessory in self.accessories]
