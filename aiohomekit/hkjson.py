#
# Copyright 2021 aiohomekit team
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

import json

import commentjson


def loads(s):
    """Load json or fallback to commentjson.

    We try to load the json with built-in json, and
    if it fails with JSONDecodeError we fallback to
    the slower but more tolerant commentjson to
    accomodate devices that use trailing commas
    in their json since iOS allows it.

    This approach ensures only devices that produce
    the technically invalid json have to pay the
    price of the double decode attempt.
    """
    try:
        return json.loads(s)
    except json.JSONDecodeError:
        return commentjson.loads(s)
