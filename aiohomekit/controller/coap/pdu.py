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

from enum import Enum
import logging
import struct

from aiohomekit.enum import EnumWithDescription

logger = logging.getLogger(__name__)


class OpCode(Enum):
    CHAR_SIG_READ = 0x01
    CHAR_WRITE = 0x02
    CHAR_READ = 0x03
    CHAR_TIMED_WRITE = 0x04
    CHAR_EXEC_WRITE = 0x05
    SERV_SIG_READ = 0x06
    UNK_09_READ_GATT = 0x09
    UNK_0B_SUBSCRIBE = 0x0B
    UNK_0C_UNSUBSCRIBE = 0x0C


class PDUStatus(EnumWithDescription):
    SUCCESS = 0, "Success"
    UNSUPPORTED_PDU = 1, "Unsupported PDU"
    MAX_PROCEDURES = 2, "Max procedures"
    INSUFFICIENT_AUTHORIZATION = 3, "Insufficient authorization"
    INVALID_INSTANCE_ID = 4, "Invalid instance ID"
    INSUFFICIENT_AUTHENTICATION = 5, "Insufficient authentication"
    INVALID_REQUEST = 6, "Invalid request"
    # custom error states
    TID_MISMATCH = 256, "Transaction ID mismatch"
    BAD_CONTROL = 257, "Control field doesn't have expected bits set"


def encode_pdu(opcode: OpCode, tid: int, iid: int, data: bytes) -> bytes:
    buf = struct.pack("<BBBHH", 0b00000000, opcode.value, tid, iid, len(data))
    return bytes(buf + data)


def encode_all_pdus(opcode: OpCode, iids: list[int], data: list[bytes]) -> bytes:
    iids_data = zip(iids, data)
    req_pdu = b"".join(
        [
            encode_pdu(
                opcode,
                idx,
                iid_data[0],
                iid_data[1],
            )
            for (idx, iid_data) in enumerate(iids_data)
        ]
    )
    return req_pdu


def decode_pdu(expected_tid: int, data: bytes) -> tuple[int, bytes | PDUStatus]:
    control, tid, status, body_len = struct.unpack("<BBBH", data[0:5])
    status = PDUStatus(status)

    logger.debug(
        "Got PDU Control=0x%02x, TID=0x%02x, Status=%s, Len=%d"
        % (
            control,
            tid,
            status.description,
            body_len,
        )
    )

    if tid != expected_tid:
        logger.warning(f"Expected transaction {expected_tid} but got transaction {tid}")
        return (body_len, PDUStatus.TID_MISMATCH)

    if status != PDUStatus.SUCCESS:
        logger.warning(
            f"Transaction {tid} failed with error {status} ({status.description}"
        )
        return (body_len, status)

    if control & 0b0000_1110 != 0b0000_0010:
        logger.warning(f"Transaction {tid} control doesn't have response bit set")
        return (body_len, PDUStatus.BAD_CONTROL)

    return body_len, data[5 : 5 + body_len]


def decode_all_pdus(
    starting_tid: int, data: bytes
) -> list[tuple[int, bytes | PDUStatus]]:
    idx = starting_tid
    offset = 0
    res = []
    while True:
        body_len, body = decode_pdu(idx, data[offset:])
        res.append(body)

        idx += 1
        offset += 5 + body_len
        if offset >= len(data):
            break

    return res
