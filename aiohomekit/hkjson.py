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
import re
from typing import Any

import orjson

JSON_ENCODE_EXCEPTIONS = (TypeError, ValueError)
JSON_DECODE_EXCEPTIONS = (json.JSONDecodeError, orjson.JSONDecodeError, ValueError)

_TRAILING_COMMA_RE = re.compile(r'("(?:\\.|[^"\\])*")|,(?=\s*[}\]])')


def _strip_trailing_commas(text: str) -> str:
    """Remove trailing commas before } or ], ignoring commas inside strings."""
    return _TRAILING_COMMA_RE.sub(lambda match: match.group(1) or "", text)


def loads(s: str | bytes | bytearray | memoryview) -> Any:
    """Load json or fallback to stripping trailing commas.

    We try to load the json with orjson, and if it
    fails with JSONDecodeError we strip any trailing
    commas and try again to accomodate devices that
    use trailing commas in their json since iOS
    allows it.

    This approach ensures only devices that produce
    the technically invalid json have to pay the
    price of the double decode attempt.
    """
    try:
        return orjson.loads(s)
    except orjson.JSONDecodeError:
        try:
            text = s if isinstance(s, str) else bytes(s).decode("utf-8")
            return orjson.loads(_strip_trailing_commas(text))
        except (orjson.JSONDecodeError, UnicodeDecodeError) as ex:
            raise ValueError(f"Failed to parse JSON: {ex}") from ex


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
