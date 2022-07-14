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

import os

BLE_TRANSPORT_SUPPORTED = False
COAP_TRANSPORT_SUPPORTED = False
IP_TRANSPORT_SUPPORTED = False

try:
    if "AIOHOMEKIT_TRANSPORT_BLE" in os.environ:
        __import__("bleak")
        BLE_TRANSPORT_SUPPORTED = True
except ModuleNotFoundError:
    pass

try:
    if "AIOHOMEKIT_TRANSPORT_COAP" in os.environ:
        __import__("aiocoap")
        COAP_TRANSPORT_SUPPORTED = True
except ModuleNotFoundError:
    pass

try:
    __import__("zeroconf")
    IP_TRANSPORT_SUPPORTED = True
except ModuleNotFoundError:
    pass
