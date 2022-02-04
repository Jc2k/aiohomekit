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

from enum import Enum, IntEnum
import logging
import struct

logger = logging.getLogger(__name__)


class OpCode(Enum):

    CHAR_SIG_READ = 0x01
    CHAR_WRITE = 0x02
    CHAR_READ = 0x03
    CHAR_TIMED_WRITE = 0x04
    CHAR_EXEC_WRITE = 0x05
    SERV_SIG_READ = 0x06


class PDUStatus(IntEnum):

    SUCCESS = 0
    UNSUPPORTED_PDU = 1
    MAX_PROCEDURES = 2
    INSUFFICIENT_AUTHORIZATION = 3
    INVALID_INSTANCE_ID = 4
    INSUFFICIENT_AUTHENTICATION = 5
    INVALID_REQUEST = 6


def encode_pdu(opcode: OpCode, tid: int, iid: int, data: bytes | None = None) -> bytes:
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
    status = PDUStatus(status)

    logger.debug(
        "Get PDU %s: TID %02x (Expected: %s), Status:%s, Len:%d",
        control & 0b00001110 == 0b00000010 and "response" or "request",
        tid,
        expected_tid,
        status,
        len(data) - 5,
    )

    if tid != expected_tid:
        raise ValueError(
            f"Expected transaction {expected_tid} but got transaction {tid}"
        )

    if status != PDUStatus.SUCCESS:
        raise ValueError(f"Transaction {tid} failed with error {status}")

    if len(data) < 5:
        return 0, b""

    expected_length = struct.unpack("<H", data[3:5])[0]

    return expected_length, data[5:]
