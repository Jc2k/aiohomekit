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
