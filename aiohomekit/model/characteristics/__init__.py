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

from .characteristic import Characteristic
from .characteristic_formats import CharacteristicFormats
from .characteristic_types import CharacteristicsTypes
from .const import (
    ActivationStateValues,
    CurrentFanStateValues,
    CurrentHeaterCoolerStateValues,
    CurrentMediaStateValues,
    HeatingCoolingCurrentValues,
    HeatingCoolingTargetValues,
    InputEventValues,
    InUseValues,
    IsConfiguredValues,
    ProgramModeValues,
    RemoteKeyValues,
    SwingModeValues,
    TargetFanStateValues,
    TargetHeaterCoolerStateValues,
    TargetMediaStateValues,
    ValveTypeValues,
)
from .permissions import CharacteristicPermissions
from .types import CharacteristicShortUUID, CharacteristicUUID
from .units import CharacteristicUnits

EVENT_CHARACTERISTICS = {
    CharacteristicsTypes.INPUT_EVENT,
    CharacteristicsTypes.BUTTON_EVENT,
}
# These characteristics are marked as [pr,ev] but make no sense to poll.
#
# Doing so can cause phantom triggers.


__all__ = [
    "EVENT_CHARACTERISTICS",
    "ActivationStateValues",
    "Characteristic",
    "CharacteristicFormats",
    "CharacteristicPermissions",
    "CharacteristicShortUUID",
    "CharacteristicUUID",
    "CharacteristicUnits",
    "CharacteristicsTypes",
    "CurrentFanStateValues",
    "CurrentHeaterCoolerStateValues",
    "CurrentMediaStateValues",
    "HeatingCoolingCurrentValues",
    "HeatingCoolingTargetValues",
    "InUseValues",
    "InputEventValues",
    "IsConfiguredValues",
    "ProgramModeValues",
    "RemoteKeyValues",
    "SwingModeValues",
    "TargetFanStateValues",
    "TargetHeaterCoolerStateValues",
    "TargetMediaStateValues",
    "ValveTypeValues",
]
