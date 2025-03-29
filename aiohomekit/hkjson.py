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
from __future__ import annotations

import json
from typing import Any

import commentjson
import orjson

JSON_ENCODE_EXCEPTIONS = (TypeError, ValueError)
JSON_DECODE_EXCEPTIONS = (json.JSONDecodeError, orjson.JSONDecodeError)


def loads(s: str | bytes | bytearray | memoryview) -> Any:
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
        return orjson.loads(s)
    except orjson.JSONDecodeError:
        return commentjson.loads(s)


def dumps(data: Any) -> str:
    """JSON encoder that uses orjson."""
    return dump_bytes(data).decode("utf-8")


def dump_bytes(data: Any) -> str:
    """JSON encoder that works with iOS.

    An iPhone sends JSON like this:

    {"characteristics":[{"iid":15,"aid":2,"ev":true}]}

    Some devices (Tado Internet Bridge) depend on this some of the time.

    orjson natively generates output with no spaces.
    """
    return orjson.dumps(data, option=orjson.OPT_NON_STR_KEYS)


def dumps_indented(data: Any) -> str:
    """JSON encoder that uses orjson with indent."""
    return orjson.dumps(
        data,
        option=orjson.OPT_INDENT_2 | orjson.OPT_NON_STR_KEYS,
    ).decode("utf-8")
