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


class _ServicesTypes:
    """
    This data is taken from chapter 9 page 216 onwards.
    """

    ACCESSORY_INFORMATION = "3E"
    AIR_PURIFIER = "BB"
    AIR_QUALITY_SENSOR = "8D"
    BATTERY_SERVICE = "96"
    CAMERA_RTP_STREAM_MANAGEMENT = "110"
    CARBON_DIOXIDE_SENSOR = "97"
    CARBON_MONOXIDE_SENSOR = "7F"
    CONTACT_SENSOR = "80"
    DOOR = "81"
    DOORBELL = "121"
    FAN = "40"
    FAN_V2 = "B7"
    FILTER_MAINTENANCE = "BA"
    FAUCET = "D7"
    GARAGE_DOOR_OPENER = "41"
    HEATER_COOLER = "BC"
    HUMIDIFIER_DEHUMIDIFIER = "BD"
    HUMIDITY_SENSOR = "82"
    INPUT_SOURCE = "D9"
    IRRIGATION_SYSTEM = "CF"
    LEAK_SENSOR = "83"
    LIGHT_SENSOR = "84"
    LIGHTBULB = "43"
    LOCK_MANAGEMENT = "44"
    LOCK_MECHANISM = "45"
    MICROPHONE = "112"
    MOTION_SENSOR = "85"
    OCCUPANCY_SENSOR = "86"
    OUTLET = "47"
    SECURITY_SYSTEM = "7E"
    SERVICE_LABEL = "CC"
    SLAT = "B9"
    SMOKE_SENSOR = "87"
    SPEAKER = "113"
    STATELESS_PROGRAMMABLE_SWITCH = "89"
    SWITCH = "49"
    TELEVISION = "D8"
    TEMPERATURE_SENSOR = "8A"
    THERMOSTAT = "4A"
    THHREAD_TRANSPORT = "701"
    VALVE = "D0"
    WINDOW = "8B"
    WINDOW_COVERING = "8C"

    def __init__(self) -> None:
        self.baseUUID = "-0000-1000-8000-0026BB765291"

    def get_uuid(self, item_name: str) -> str:
        """
        Returns the full length UUID for either a shorted UUID or textual characteristic type name. For information on
        full and short UUID consult chapter 5.6.1 page 72 of the specification. It also supports to pass through full
        HomeKit UUIDs.

        :param item_name: either the type name (e.g. "public.hap.characteristic.position.current") or the short UUID or
                          a HomeKit specific full UUID.
        :return: the full UUID (e.g. "0000006D-0000-1000-8000-0026BB765291")
        :raises KeyError: if the input is neither a short UUID nor a type name. Specific error is given in the message.
        """
        if len(item_name) == 36:
            return item_name.upper()

        if len(item_name) <= 8:
            prefix = "0" * (8 - len(item_name))
            return f"{prefix}{item_name}{self.baseUUID}"

        raise KeyError(f"{item_name} not a valid UUID or short UUID")

    def get_short_uuid(self, item_name: str) -> str:
        """
        Returns the short UUID for either a full UUID or textual service type name. For information on
        full and short UUID consult chapter 5.6.1 page 72 of the specification. It also supports to pass through full
        non-HomeKit UUIDs.

        :param item_name: either the type name (e.g. "public.hap.characteristic.position.current") or the short UUID as
                          string or a HomeKit specific full UUID.
        :return: the short UUID (e.g. "6D" instead of "0000006D-0000-1000-8000-0026BB765291")
        :raises KeyError: if the input is neither a UUID nor a type name. Specific error is given in the message.
        """
        if item_name.upper().endswith(self.baseUUID):
            item_name = item_name.upper()
            item_name = item_name.split("-", 1)[0]
            return item_name.lstrip("0")

        return item_name.upper()


#
#   Have a singleton to avoid overhead
#
ServicesTypes = _ServicesTypes()
