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

"""
Typing hints for the serialization format used by the JSON part of the HomeKit API.
"""

from __future__ import annotations

from typing import TypedDict, Union

Characteristic = TypedDict(
    "Characteristic",
    {
        "type": str,
        "iid": int,
        "description": str,
        "value": Union[str, float, int, bool],
        "perms": list[str],
        "unit": str,
        "format": str,
        "valid-values": list[int],
        "minValue": Union[int, float],
        "maxValue": Union[int, float],
        "minStep": Union[int, float],
        "minLen": int,
    },
    total=False,
)


class Service(TypedDict, total=False):
    type: str
    iid: int
    characteristics: list[Characteristic]
    linked: list[int]


class Accessory(TypedDict, total=True):
    aid: int
    services: list[Service]


Accesories = list[Accessory]
