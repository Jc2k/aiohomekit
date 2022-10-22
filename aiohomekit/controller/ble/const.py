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

from enum import IntEnum

HAP_MIN_REQUIRED_MTU = 100


class AdditionalParameterTypes(IntEnum):
    # Additional Parameter Types for BLE (Table 6-9 page 98)
    Value = 0x01
    AdditionalAuthorizationData = 0x02
    Origin = 0x03
    CharacteristicType = 0x04
    CharacteristicInstanceId = 0x05
    ServiceType = 0x06
    ServiceInstanceId = 0x07
    TTL = 0x08
    ParamReturnResponse = 0x09
    HAPCharacteristicPropertiesDescriptor = 0x0A
    GATTUserDescriptionDescriptor = 0x0B
    GATTPresentationFormatDescriptor = 0x0C
    GATTValidRange = 0x0D
    HAPStepValueDescriptor = 0x0E
    HAPServiceProperties = 0x0F
    HAPLinkedServices = 0x10
    HAPValidValuesDescriptor = 0x11
    HAPValidValuesRangeDescriptor = 0x12
