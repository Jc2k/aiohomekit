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
import pytest

import aiohomekit.hkjson as hkjson


def test_loads_trailing_comma():
    """Test we can decode with a trailing comma."""
    result = hkjson.loads(
        '{"characteristics":[{"aid":10,"iid":12,"value":27.0},{"aid":10,"iid":13,"value":20.5},]}'
    )
    assert result == {
        "characteristics": [
            {"aid": 10, "iid": 12, "value": 27.0},
            {"aid": 10, "iid": 13, "value": 20.5},
        ]
    }


def test_loads_empty_document():
    """Test that empty document raises ValueError instead of lark error."""
    with pytest.raises(ValueError, match="Failed to parse JSON"):
        hkjson.loads("")


def test_loads_valid_json() -> None:
    """Test that valid json still decodes on the fast path."""
    result = hkjson.loads('{"characteristics":[{"aid":10,"iid":12,"value":27.0}]}')
    assert result == {"characteristics": [{"aid": 10, "iid": 12, "value": 27.0}]}


def test_loads_trailing_comma_in_object() -> None:
    """Test we can decode an object with a trailing comma."""
    assert hkjson.loads('{"a": 1,}') == {"a": 1}


def test_loads_trailing_comma_with_whitespace() -> None:
    """Test we can decode a trailing comma followed by whitespace."""
    assert hkjson.loads('{"a": [1, 2, \n ] , \n }') == {"a": [1, 2]}


def test_loads_trailing_commas_nested() -> None:
    """Test we can decode trailing commas at multiple nesting levels."""
    assert hkjson.loads('{"a": [1, 2,], "b": {"c": 1,},}') == {
        "a": [1, 2],
        "b": {"c": 1},
    }


def test_loads_comma_inside_string_untouched() -> None:
    """Test commas followed by brackets inside strings are preserved."""
    assert hkjson.loads('{"a": ",]", "b": "x,}",}') == {"a": ",]", "b": "x,}"}


def test_loads_escaped_quote_inside_string() -> None:
    """Test escaped quotes inside strings do not confuse the parser."""
    assert hkjson.loads('{"a": "say \\",]\\"",}') == {"a": 'say ",]"'}


def test_loads_string_ending_with_escaped_backslash() -> None:
    """Test a string ending in an escaped backslash."""
    assert hkjson.loads('{"a": "c:\\\\",}') == {"a": "c:\\"}


def test_loads_trailing_comma_bytes_input() -> None:
    """Test we can decode bytes, bytearray and memoryview input."""
    raw = b'{"a": [1,],}'
    expected = {"a": [1]}
    assert hkjson.loads(raw) == expected
    assert hkjson.loads(bytearray(raw)) == expected
    assert hkjson.loads(memoryview(raw)) == expected


def test_loads_doubled_comma_raises() -> None:
    """Test a doubled comma is still invalid."""
    with pytest.raises(ValueError, match="Failed to parse JSON"):
        hkjson.loads("[1,,]")


def test_loads_garbage_raises() -> None:
    """Test garbage input raises ValueError."""
    with pytest.raises(ValueError, match="Failed to parse JSON"):
        hkjson.loads("not json at all")


def test_loads_comments_rejected() -> None:
    """Test json with comments is no longer accepted."""
    with pytest.raises(ValueError, match="Failed to parse JSON"):
        hkjson.loads('{"a": 1} // note')


def test_loads_invalid_utf8_raises() -> None:
    """Test invalid utf-8 bytes raise ValueError."""
    with pytest.raises(ValueError, match="Failed to parse JSON"):
        hkjson.loads(b'{"a": "\xff",}')
