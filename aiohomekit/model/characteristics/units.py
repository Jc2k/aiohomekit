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


class CharacteristicUnits:
    """
    See table 5-6 page 68
    """

    celsius = "celsius"
    percentage = "percentage"
    arcdegrees = "arcdegrees"
    lux = "lux"
    seconds = "seconds"


class BleCharacteristicUnits:
    """
    Mapping taken from Table 6-37 page 130 and https://www.bluetooth.com/specifications/assigned-numbers/units
    """

    celsius = 0x272F
    arcdegrees = 0x2763
    percentage = 0x27AD
    unitless = 0x2700
    lux = 0x2731
    seconds = 0x2703
