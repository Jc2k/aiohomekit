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
from typing import Iterable

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


def encode_pdu(
    opcode: OpCode,
    tid: int,
    iid: int,
    data: bytes | None = None,
    fragment_size: int = 512,
) -> Iterable[bytes]:
    """
    Encodes a PDU.

    The header is required, but the body (including length) is optional.

    For BLE, the PDU must be fragmented to fit into ATT_MTU. The default here is 512.
    In a secure session this drops to 496 (16 bytes for the encryption). Some devices
    drop this quite a bit.
    """
    retval = struct.pack("<BBBH", 0, opcode.value, tid, iid)
    if not data:
        yield retval
        return

    # Full header + body size + data
    next_size = fragment_size - 7

    yield bytes(retval + struct.pack("<H", len(data)) + data[:next_size])
    data = data[next_size:]

    # Control + tid + data
    next_size = fragment_size - 2
    for i in range(0, len(data), next_size):
        yield struct.pack("<BB", 0x80, tid) + data[i : i + next_size]


def decode_pdu(expected_tid: int, data: bytes) -> tuple[bool, bytes]:
    control, tid, status = struct.unpack("<BBB", data[:3])
    status = PDUStatus(status)

    logger.debug(
        "Got PDU %s: TID %02x (Expected: %02x), Status:%s, Len:%d",
        control,
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
    data = data[5:]

    return expected_length, data


def decode_pdu_continuation(expected_tid, data):
    control, tid = struct.unpack("<BB", data[:2])

    logger.debug(
        "Got PDU %x: TID %02x (Expected: %02x) Len:%d",
        control,
        tid,
        expected_tid,
        len(data) - 2,
    )

    if not (control & 0x80):
        raise ValueError("Expected continuation flag but isn't set")

    if tid != expected_tid:
        raise ValueError(
            f"Expected transaction {expected_tid} but got transaction {tid}"
        )

    return data[2:]
