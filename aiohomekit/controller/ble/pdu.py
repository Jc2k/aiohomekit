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

from __future__ import annotations

import struct

from .const import OpCodes


def encode_pdu(opcode: OpCodes, tid: int, iid: int, data: bytes | None = None) -> bytes:
    """
    Encodes a PDU.

    The header is required, but the body (including length) is optional.
    """
    retval = struct.pack("<BBBH", 0, opcode.value, tid, iid)
    if not data:
        return retval
    return bytes(retval + struct.pack("<H", len(data)) + data)


def decode_pdu(expected_tid: int, data: bytes) -> tuple[int, bytes]:
    control, tid, status = struct.unpack("<BBB", data[:3])

    if tid != expected_tid:
        raise ValueError(
            f"Expected transaction {expected_tid} but got transaction {tid}"
        )

    if status != 0:
        raise ValueError(f"Transaction {tid} failed with error {status}")

    if len(data) < 5:
        return 0, b""

    expected_length = struct.unpack("<H", data[3:5])
    return expected_length, data[5:]
