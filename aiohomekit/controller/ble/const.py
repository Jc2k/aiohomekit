from enum import IntEnum, Enum

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
    HAPCharacteristicPropertiesDescriptor = 0x0a
    GATTUserDescriptionDescriptor = 0x0b
    GATTPresentationFormatDescriptor = 0x0c
    GATTValidRange = 0x0d
    HAPStepValueDescriptor = 0x0e
    HAPServiceProperties = 0x0f
    HAPLinkedServices = 0x10
    HAPValidValuesDescriptor = 0x11
    HAPValidValuesRangeDescriptor = 0x12

class OpCodes(Enum):
    CHAR_SIG_READ = 0x01
    CHAR_WRITE = 0x02
    CHAR_READ = 0x03
    CHAR_TIMED_WRITE = 0x04
    CHAR_EXEC_WRITE = 0x05
    SERV_SIG_READ = 0x06