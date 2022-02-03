from dataclasses import dataclass

from aiohomekit.tlv8 import TLVStruct, tlv_entry, u8

from .const import AdditionalParameterTypes


@dataclass
class BleRequest(TLVStruct):
    expect_response: u8 = tlv_entry(AdditionalParameterTypes.ParamReturnResponse)
    value: bytes = tlv_entry(AdditionalParameterTypes.Value)