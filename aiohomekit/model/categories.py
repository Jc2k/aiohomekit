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


class Categories(enum.IntFlag):

    OTHER = 1
    BRIDGE = 2
    FAN = 3
    GARAGE = 4
    LIGHTBULB = 5
    DOOR_LOCK = 6
    OUTLET = 7
    SWITCH = 8
    THERMOSTAT = 9
    SENSOR = 10
    SECURITY_SYSTEM = 11
    DOOR = 12
    WINDOW = 13
    WINDOW_COVERING = 14
    PROGRAMMABLE_SWITCH = 15
    RANGE_EXTENDER = 16
    IP_CAMERA = 17
    VIDEO_DOOR_BELL = 18
    AIR_PURIFIER = 19
    HEATER = 20
    AIR_CONDITIONER = 21
    HUMIDIFIER = 22
    DEHUMIDIFER = 23
    APPLE_TV = 24
    HOMEPOD = 25
    SPEAKER = 26
    AIRPORT = 27
    SPRINKLER = 28
    FAUCET = 29
    SHOWER_HEAD = 30
    TELEVISION = 31
    REMOTE = 32
    ROUTER = 33
