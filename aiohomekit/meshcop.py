#
# Copyright 2023 aiohomekit team
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

"""
Struct for various records from Meshcop Thread systems.

https://openthread.io/reference/group/api-operational-dataset
https://github.com/openthread/openthread/blob/main/include/openthread/dataset.h
https://software-dl.ti.com/lprf/simplelink_cc26x2_sdk-1.60/docs/thread/doxygen/openthread-docs-0.01.00/html/dd/d6b/meshcop__tlvs_8hpp_source.html
https://github.com/home-assistant-libs/python-otbr-api/blob/main/python_otbr_api/tlv_parser.py
"""

from dataclasses import dataclass

from aiohomekit.tlv8 import TLVStruct, bu16, tlv_entry


@dataclass
class Meshcop(TLVStruct):
    channel: bu16 = tlv_entry(0)
    panid: bu16 = tlv_entry(1)
    extpanid: bytes = tlv_entry(2)
    networkname: str = tlv_entry(3)
    pskc: bytes = tlv_entry(4)
    networkkey: bytes = tlv_entry(5)
    network_key_sequence: bytes = tlv_entry(6)
    meshlocalprefix: bytes = tlv_entry(7)
    steering_data: bytes = tlv_entry(8)
    border_agent_rloc: bytes = tlv_entry(9)
    commissioner_id: bytes = tlv_entry(10)
    comm_session_id: bytes = tlv_entry(11)
    securitypolicy: bytes = tlv_entry(12)
    get: bytes = tlv_entry(13)
    activetimestamp: bytes = tlv_entry(14)
    state: bytes = tlv_entry(16)
    joiner_dtls: bytes = tlv_entry(17)
    joiner_udp_port: bytes = tlv_entry(18)
    joiner_iid: bytes = tlv_entry(19)
    joiner_rloc: bytes = tlv_entry(20)
    joiner_router_kek: bytes = tlv_entry(21)
    provisioning_url: bytes = tlv_entry(32)
    vendor_name_tlv: bytes = tlv_entry(33)
    vendor_model_tlv: bytes = tlv_entry(34)
    vendor_sw_version_tlv: bytes = tlv_entry(35)
    vendor_data_tlv: bytes = tlv_entry(36)
    vendor_stack_version_tlv: bytes = tlv_entry(37)
    pendingtimestamp: bytes = tlv_entry(51)
    delaytimer: bytes = tlv_entry(52)
    channelmask: bytes = tlv_entry(53)
    count: bytes = tlv_entry(54)
    period: bytes = tlv_entry(55)
    scan_duration: bytes = tlv_entry(56)
    energy_list: bytes = tlv_entry(57)
    discoveryrequest: bytes = tlv_entry(128)
    discoveryresponse: bytes = tlv_entry(129)
