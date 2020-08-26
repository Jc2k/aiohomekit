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


class _Categories:
    """
    This data is taken from Table 12-3 Accessory Categories on page 254. Values above 19 are reserved.
    Additional categories ( 20-23 pulled from
    https://github.com/abedinpour/HAS/blob/master/src/categories.ts )
    """

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

    def __init__(self) -> None:
        self._categories = {
            _Categories.OTHER: "Other",
            _Categories.BRIDGE: "Bridge",
            _Categories.FAN: "Fan",
            _Categories.GARAGE: "Garage",
            _Categories.LIGHTBULB: "Lightbulb",
            _Categories.DOOR_LOCK: "Door Lock",
            _Categories.OUTLET: "Outlet",
            _Categories.SWITCH: "Switch",
            _Categories.THERMOSTAT: "Thermostat",
            _Categories.SENSOR: "Sensor",
            _Categories.SECURITY_SYSTEM: "Security System",
            _Categories.DOOR: "Door",
            _Categories.WINDOW: "Window",
            _Categories.WINDOW_COVERING: "Window Covering",
            _Categories.PROGRAMMABLE_SWITCH: "Programmable Switch",
            _Categories.RANGE_EXTENDER: "Range Extender",
            _Categories.IP_CAMERA: "IP Camera",
            _Categories.VIDEO_DOOR_BELL: "Video Door Bell",
            _Categories.AIR_PURIFIER: "Air Purifier",
            _Categories.HEATER: "Heater",
            _Categories.AIR_CONDITIONER: "Air Conditioner",
            _Categories.HUMIDIFIER: "Humidifier",
            _Categories.DEHUMIDIFER: "Dehumidifier",
            _Categories.APPLE_TV: "Apple TV",
            _Categories.HOMEPOD: "HomePod",
            _Categories.SPEAKER: "Speaker",
            _Categories.AIRPORT: "AirPort",
            _Categories.SPRINKLER: "Sprinkler",
            _Categories.FAUCET: "Faucet",
            _Categories.SHOWER_HEAD: "Shower Head",
            _Categories.TELEVISION: "Television",
            _Categories.REMOTE: "Remote",
            _Categories.ROUTER: "Router",
        }

        self._categories_rev = {self._categories[k]: k for k in self._categories.keys()}

    def __contains__(self, item):
        if item in self._categories:
            return True

        if item in self._categories_rev:
            return True

        return False

    def __getitem__(self, item: int) -> str:
        if item in self._categories:
            return self._categories[item]

        if item in self._categories_rev:
            return self._categories_rev[item]

        return "Unknown"


Categories = _Categories()
