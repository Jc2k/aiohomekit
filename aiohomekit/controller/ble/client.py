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

import logging
import random
from typing import Any, Callable, TypeVar, cast

from bleak import BleakClient
from bleak.backends.characteristic import BleakGATTCharacteristic

from aiohomekit.controller.ble.key import DecryptionKey, EncryptionKey
from aiohomekit.exceptions import EncryptionError
from aiohomekit.model.services import ServicesTypes
from aiohomekit.pdu import (
    OpCode,
    PDUStatus,
    decode_pdu,
    decode_pdu_continuation,
    encode_pdu,
)
from aiohomekit.protocol.tlv import TLV

from .bleak import BLEAK_EXCEPTIONS, AIOHomeKitBleakClient
from .const import AdditionalParameterTypes
from .structs import BleRequest

logger = logging.getLogger(__name__)

WrapFuncType = TypeVar("WrapFuncType", bound=Callable[..., Any])

DEFAULT_ATTEMPTS = 2
MAX_REASSEMBLY = 50
ATT_HEADER_SIZE = 3
KEY_OVERHEAD_SIZE = 16


def retry_bluetooth_connection_error(attempts: int = DEFAULT_ATTEMPTS) -> WrapFuncType:
    """Define a wrapper to retry on bluetooth connection error."""

    def _decorator_retry_bluetooth_connection_error(func: WrapFuncType) -> WrapFuncType:
        """Define a wrapper to retry on bleak error.

        The accessory is allowed to disconnect us any time so
        we need to retry the operation.
        """

        async def _async_wrap(*args: Any, **kwargs: Any) -> Any:
            for attempt in range(attempts):
                try:
                    return await func(*args, **kwargs)
                except BLEAK_EXCEPTIONS:
                    if attempt == attempts - 1:
                        raise
                    logger.debug(
                        "Bleak error calling %s, retrying...", func, exc_info=True
                    )

        return cast(WrapFuncType, _async_wrap)

    return cast(WrapFuncType, _decorator_retry_bluetooth_connection_error)


def determine_fragment_size(
    client: AIOHomeKitBleakClient,
    encryption_key: EncryptionKey | None,
    handle: BleakGATTCharacteristic,
) -> int:
    """Determine the fragment size for a characteristic."""
    debug_enabled = logger.isEnabledFor(logging.DEBUG)

    # Newer bleak, not currently released
    if max_write_without_response_size := getattr(
        handle, "max_write_without_response_size", None
    ):
        if debug_enabled:
            logger.debug(
                "max_write_without_response_size: %s, mtu_size-3: %s",
                max_write_without_response_size,
                client.mtu_size - ATT_HEADER_SIZE,
            )
        fragment_size = max(
            max_write_without_response_size, client.mtu_size - ATT_HEADER_SIZE
        )
    # Bleak 0.15.1 and below
    elif (
        (char_obj := getattr(handle, "obj", None))
        and isinstance(char_obj, dict)
        and (char_mtu := char_obj.get("MTU"))
    ):
        if debug_enabled:
            logger.debug(
                "bleak obj MTU: %s, mtu_size-3: %s",
                char_mtu,
                client.mtu_size - ATT_HEADER_SIZE,
            )
        fragment_size = max(
            char_mtu - ATT_HEADER_SIZE, client.mtu_size - ATT_HEADER_SIZE
        )
    else:
        if debug_enabled:
            logger.debug(
                "no bleak obj MTU or max_write_without_response_size, using mtu_size-3: %s",
                client.mtu_size - ATT_HEADER_SIZE,
            )
        fragment_size = client.mtu_size - ATT_HEADER_SIZE

    if encryption_key:
        # Secure session means an extra 16 bytes of overhead
        fragment_size -= KEY_OVERHEAD_SIZE

    if debug_enabled:
        logger.debug("Using fragment size: %s", fragment_size)

    return fragment_size


async def ble_request(
    client: AIOHomeKitBleakClient,
    encryption_key: EncryptionKey | None,
    decryption_key: DecryptionKey | None,
    opcode: OpCode,
    handle: BleakGATTCharacteristic,
    iid: int,
    data: bytes | None = None,
) -> tuple[PDUStatus, bytes]:
    """Send a request to the accessory."""
    tid = random.randrange(1, 254)
    await write_pdu(client, encryption_key, opcode, handle, iid, data, tid)
    return await read_pdu(client, decryption_key, handle, tid)


async def write_pdu(
    client: AIOHomeKitBleakClient,
    encryption_key: EncryptionKey,
    opcode: OpCode,
    handle: BleakGATTCharacteristic,
    iid: int,
    data: bytes,
    tid: int,
) -> None:
    """Write a PDU to the accessory."""
    fragment_size = determine_fragment_size(client, encryption_key, handle)
    # Wrap data in one or more PDU's split at fragment_size
    # And write each one to the target characterstic handle
    writes = []
    for data in encode_pdu(opcode, tid, iid, data, fragment_size):
        logger.debug("Queuing fragment for write: %s", data)
        if encryption_key:
            data = encryption_key.encrypt(data)
        writes.append(data)

    for write in writes:
        await client.write_gatt_char(handle, write, True)


async def read_pdu(
    client: AIOHomeKitBleakClient,
    decryption_key: DecryptionKey | None,
    handle: BleakGATTCharacteristic,
    tid: int,
) -> tuple[PDUStatus, bytes]:
    """Read a PDU from a characteristic."""
    data = await client.read_gatt_char(handle)
    if decryption_key:
        data = decryption_key.decrypt(data)
        if data is False:
            raise EncryptionError("Decryption failed")

    logger.debug("Read fragment: %s", data)

    # Validate the PDU header
    status, expected_length, data = decode_pdu(tid, data)

    # If packet is too short then there may be 1 or more continuation
    # packets. Keep reading until we have enough data.
    #
    # Even if the status is failure, we must read the whole
    # data set or the encryption will be out of sync.
    #
    while len(data) < expected_length:
        next = await client.read_gatt_char(handle)
        if decryption_key:
            next = decryption_key.decrypt(next)
            if next is False:
                raise EncryptionError("Decryption failed")
        logger.debug("Read fragment: %s", next)

        data += decode_pdu_continuation(tid, next)

    return status, data


def raise_for_pdu_status(client: BleakClient, pdu_status: PDUStatus) -> None:
    """Raise on non-success PDU status."""
    if pdu_status != PDUStatus.SUCCESS:
        raise ValueError(
            f"{client.address}: PDU status was not success: {pdu_status.description} ({pdu_status.value})"
        )


def decode_pdu_tlv_value(
    client: AIOHomeKitBleakClient, pdu_status: PDUStatus, data: bytes
) -> bytes:
    """Decode the TLV value from the PDU."""
    raise_for_pdu_status(client, pdu_status)
    decoded = dict(TLV.decode_bytes(data))
    return decoded[AdditionalParameterTypes.Value.value]


async def char_write(
    client: BleakClient,
    encryption_key: EncryptionKey | None,
    decryption_key: DecryptionKey | None,
    handle: BleakGATTCharacteristic,
    iid: int,
    body: bytes,
) -> bytes:
    body = BleRequest(expect_response=1, value=body).encode()
    return decode_pdu_tlv_value(
        client,
        *await ble_request(
            client, encryption_key, decryption_key, OpCode.CHAR_WRITE, handle, iid, body
        ),
    )


async def pairing_char_write(
    client: AIOHomeKitBleakClient,
    handle: BleakGATTCharacteristic,
    iid: int,
    request: list[tuple[TLV, bytes]],
) -> dict[int, bytes]:
    """Read or write a characteristic value."""
    complete_data = bytearray()
    next_write = TLV.encode_list(request)
    tid = random.randrange(1, 254)
    body = BleRequest(expect_response=1, value=next_write).encode()
    await write_pdu(client, None, OpCode.CHAR_WRITE, handle, iid, body, tid)

    for _ in range(MAX_REASSEMBLY):
        decoded = TLV.decode_bytearray(
            decode_pdu_tlv_value(client, *await read_pdu(client, None, handle, tid))
        )
        if TLV.kTLVType_FragmentLast in decoded:
            logger.debug("%s: Reassembling final fragment", client.address)
            complete_data.extend(decoded[TLV.kTLVType_FragmentLast])
            return dict(TLV.decode_bytes(complete_data))
        elif TLV.kTLVType_FragmentData in decoded:
            logger.debug("%s: Reassembling fragment", client.address)
            # There is more data, acknowledge the fragment
            # and keep reading
            complete_data.extend(decoded[TLV.kTLVType_FragmentData])
            # Acknowledge the fragment
            await client.write_gatt_char(
                handle, TLV.encode_list([(TLV.kTLVType_FragmentData, b"")]), True
            )
        else:
            logger.debug("%s: Data is not fragemented", client.address)
            return decoded


async def char_read(
    client: AIOHomeKitBleakClient,
    encryption_key: EncryptionKey | None,
    decryption_key: DecryptionKey | None,
    handle: BleakGATTCharacteristic,
    iid: int,
) -> bytes:
    """Read a characteristic value."""
    return decode_pdu_tlv_value(
        client,
        *await ble_request(
            client, encryption_key, decryption_key, OpCode.CHAR_READ, handle, iid
        ),
    )


async def drive_pairing_state_machine(
    client: AIOHomeKitBleakClient,
    characteristic: str,
    state_machine: Any,
) -> Any:
    char = client.get_characteristic(ServicesTypes.PAIRING, characteristic)
    iid = await client.get_characteristic_iid(char)

    request, expected = state_machine.send(None)
    while True:
        try:
            decoded = await pairing_char_write(client, char, iid, request)
            request, expected = state_machine.send(decoded)
        except StopIteration as result:
            return result.value
