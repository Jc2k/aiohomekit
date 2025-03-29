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

import pytest
from aiohomekit.pdu import (
    OpCode,
    PDUStatus,
    decode_pdu,
    decode_pdu_continuation,
    encode_pdu,
)


def test_encode():
    assert list(encode_pdu(OpCode.CHAR_SIG_READ, 55, 1)) == [b"\x00\x017\x01\x00"]


def test_encode_with_body():
    assert list(encode_pdu(OpCode.CHAR_SIG_READ, 44, 1, b"SOMEDATA")) == [
        b"\x00\x01,\x01\x00\x08\x00SOMEDATA"
    ]


def test_encode_with_fragments():
    result = list(
        encode_pdu(OpCode.CHAR_SIG_READ, 44, 1, b"ABCD" * 64, fragment_size=256)
    )

    assert result == [
        b"\x00\x01,\x01\x00\x00\x01ABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDA"
        b"BCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDA"
        b"BCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDA"
        b"BCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDA",
        b"\x80,BCDABCD",
    ]


def test_decode():
    assert decode_pdu(23, b"\x00\x17\x00") == (PDUStatus.SUCCESS, 0, b"")


def test_decode_with_body():
    assert decode_pdu(23, b"\x00\x17\x00\x08\x00SOMEDATA") == (
        PDUStatus.SUCCESS,
        8,
        b"SOMEDATA",
    )


def test_decode_invalid_tid():
    with pytest.raises(ValueError):
        decode_pdu(24, b"\x00\x17\x00")


def test_decode_invalid_status():
    assert decode_pdu(23, b"\x00\x17\x01") == (PDUStatus.UNSUPPORTED_PDU, 0, b"")


def test_decode_continuation():
    assert decode_pdu_continuation(23, b"\x80\x17SOMEDATA") == b"SOMEDATA"


def test_decode_continuation_invalid_cbit():
    with pytest.raises(ValueError):
        decode_pdu_continuation(23, b"\x00\x17SOMEDATA")


def test_decode_continuation_invalid_tid():
    with pytest.raises(ValueError):
        decode_pdu_continuation(24, b"\x80\x17SOMEDATA")
