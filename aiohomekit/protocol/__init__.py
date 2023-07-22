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
from __future__ import annotations

from binascii import hexlify
from collections.abc import Generator
import logging
from typing import Any, Callable

from cryptography import exceptions as cryptography_exceptions
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519, x25519

from aiohomekit.crypto import (
    NONCE_PADDING,
    ChaCha20Poly1305Decryptor,
    ChaCha20Poly1305Encryptor,
    SrpClient,
    hkdf_derive,
)
from aiohomekit.exceptions import (
    AuthenticationError,
    BackoffError,
    BusyError,
    IllegalData,
    IncorrectPairingIdError,
    InvalidAuthTagError,
    InvalidError,
    InvalidSignatureError,
    MaxPeersError,
    MaxTriesError,
    UnavailableError,
)
from aiohomekit.protocol.tlv import TLV

logger = logging.getLogger(__name__)


def error_handler(error: bytearray, stage: str):
    """
    Transform the various error messages defined in table 4-5 page 60 into exceptions

    :param error: the kind of error
    :param stage: the stage it appeared in
    :return: None
    """
    if error == TLV.kTLVError_Unavailable:
        raise UnavailableError(stage)
    elif error == TLV.kTLVError_Authentication:
        raise AuthenticationError(stage)
    elif error == TLV.kTLVError_Backoff:
        raise BackoffError(stage)
    elif error == TLV.kTLVError_MaxPeers:
        raise MaxPeersError(stage)
    elif error == TLV.kTLVError_MaxTries:
        raise MaxTriesError(stage)
    elif error == TLV.kTLVError_Busy:
        raise BusyError(stage)
    else:
        raise InvalidError(stage)


def handle_state_step(tlv_dict, expected_state):
    actual_state = tlv_dict.get(TLV.kTLVType_State)

    if actual_state is None:
        # Some devices go against the spec and don't include kTLVType_State
        # https://github.com/Jc2k/aiohomekit/issues/20
        # iOS tolerates this, so we do do
        return

    if actual_state != expected_state:
        raise InvalidError(f"Exepected state {expected_state} but got {actual_state}")

    if TLV.kTLVType_Error in tlv_dict:
        error_handler(tlv_dict[TLV.kTLVType_Error], f"step {expected_state}")


def perform_pair_setup_part1(
    with_auth: bool = True,
) -> Generator[
    tuple[list[tuple[int, bytearray]], list[int]], None, tuple[bytearray, bytearray]
]:
    """
    Performs a pair setup operation as described in chapter 4.7 page 39 ff.

    :return: a tuple of salt and server's public key
    :raises UnavailableError: if the device is already paired
    :raises MaxTriesError: if the device received more than 100 unsuccessful pairing attempts
    :raises BusyError: if a parallel pairing is ongoing
    :raises AuthenticationError: if the verification of the device's SRP proof fails
    :raises MaxPeersError: if the device cannot accept an additional pairing
    :raises IllegalData: if the verification of the accessory's data fails
    """

    #
    # Step #1 ios --> accessory (send SRP start Request) (see page 39)
    #
    logger.debug("#1 ios -> accessory: send SRP start request")
    request_tlv = [
        (TLV.kTLVType_State, TLV.M1),
        (TLV.kTLVType_Method, TLV.PairSetupWithAuth if with_auth else TLV.PairSetup),
    ]

    step2_expectations = [
        TLV.kTLVType_State,
        TLV.kTLVType_Error,
        TLV.kTLVType_PublicKey,
        TLV.kTLVType_Salt,
    ]
    response_tlv = yield (request_tlv, step2_expectations)

    #
    # Step #3 ios --> accessory (send SRP verify request) (see page 41)
    #
    logger.debug("#3 ios -> accessory: send SRP verify request")
    response_tlv = dict(response_tlv)
    handle_state_step(response_tlv, TLV.M2)

    if TLV.kTLVType_PublicKey not in response_tlv:
        raise InvalidError("M2: Accessory did not send public key")

    if TLV.kTLVType_Salt not in response_tlv:
        raise InvalidError("M2: Accessory did not send salt")

    return response_tlv[TLV.kTLVType_Salt], response_tlv[TLV.kTLVType_PublicKey]


def validate_mfi(session_key, response_tlv):
    # If pairing method is PairSetupWithAuth there should be an EncryptedData TLV in M4
    # It should have a signature and a certificate from an Apple secure co-processor.
    decrypted = ChaCha20Poly1305Decryptor(session_key).decrypt(
        b"",
        NONCE_PADDING + b"PS-Msg04",
        bytes(response_tlv[TLV.kTLVType_EncryptedData]),
    )

    if not decrypted:
        logger.debug(
            "Device returned kTLVType_EncryptedData during M4 but could not decrypt"
        )
        return

    sub_tlv = TLV.decode_bytes(decrypted)

    if TLV.kTLVType_Signature not in sub_tlv:
        logger.debug(
            "QUIRK: M4: Device returned kTLVType_EncryptedData, but did not contain kTLVType_Signature"
        )
        return

    if TLV.kTLVType_Certificate not in sub_tlv:
        logger.debug(
            "QUIRK: M4: Device returned kTLVType_Signature but not kTLVType_Certificate"
        )
        return

    # Certificate appears to be X509 in DER format but with some sort of PKCS7 pre-amble.
    # cryptography doesn't seem to support that yet.

    logger.debug(
        "Found seemingly valid MFI kTLVType_Signature; we don't validate this yet"
    )


def perform_pair_setup_part2(
    pin: str, ios_pairing_id: str, salt: bytearray, server_public_key: bytearray
) -> Generator[tuple[list[tuple[int, bytearray]], list[int]], None, dict[str, str]]:
    """
    Performs a pair setup operation as described in chapter 4.7 page 39 ff.

    :param pin: the setup code from the accessory
    :param ios_pairing_id: the id of the simulated ios device
    :return: a dict with the ios device's part of the pairing information
    :raises UnavailableError: if the device is already paired
    :raises MaxTriesError: if the device received more than 100 unsuccessful pairing attempts
    :raises BusyError: if a parallel pairing is ongoing
    :raises AuthenticationError: if the verification of the device's SRP proof fails
    :raises MaxPeersError: if the device cannot accept an additional pairing
    :raises IllegalData: if the verification of the accessory's data fails
    """

    srp_client = SrpClient("Pair-Setup", pin)
    srp_client.set_salt(salt)
    srp_client.set_server_public_key(server_public_key)
    # We avoid getting the values as ints to ensure
    # we do not have a conversion issue where the values
    # have a leading zero and the resulting bytes are too
    # short to be valid.
    client_pub_key = srp_client.get_public_key_bytes()
    client_proof = srp_client.get_proof_bytes()

    response_tlv = [
        (TLV.kTLVType_State, TLV.M3),
        (TLV.kTLVType_PublicKey, client_pub_key),
        (TLV.kTLVType_Proof, client_proof),
    ]

    step4_expectations = [
        TLV.kTLVType_State,
        TLV.kTLVType_Error,
        TLV.kTLVType_Proof,
        TLV.kTLVType_EncryptedData,
    ]
    response_tlv = yield (response_tlv, step4_expectations)

    #
    # Step #5 ios --> accessory (Exchange Request) (see page 43)
    #
    logger.debug("#5 ios -> accessory: send SRP exchange request")

    # M4 Verification (page 43)
    response_tlv = dict(response_tlv)
    handle_state_step(response_tlv, TLV.M4)

    if TLV.kTLVType_Proof not in response_tlv:
        raise InvalidError("M5: not an error or a proof")

    if not srp_client.verify_servers_proof_bytes(response_tlv[TLV.kTLVType_Proof]):
        raise AuthenticationError("Step #5: wrong proof!")

    # M5 Request generation (page 44)
    session_key_bytes = srp_client.get_session_key_bytes()

    ios_device_ltsk = ed25519.Ed25519PrivateKey.generate()
    ios_device_ltpk = ios_device_ltsk.public_key()
    ios_device_public_bytes = ios_device_ltpk.public_bytes(
        encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw
    )

    # reversed:
    #   Pair-Setup-Encrypt-Salt instead of Pair-Setup-Controller-Sign-Salt
    #   Pair-Setup-Encrypt-Info instead of Pair-Setup-Controller-Sign-Info
    ios_device_x = hkdf_derive(
        session_key_bytes,
        b"Pair-Setup-Controller-Sign-Salt",
        b"Pair-Setup-Controller-Sign-Info",
    )

    session_key = hkdf_derive(
        session_key_bytes,
        b"Pair-Setup-Encrypt-Salt",
        b"Pair-Setup-Encrypt-Info",
    )

    # if TLV.kTLVType_EncryptedData in response_tlv:
    #     validate_mfi(session_key, response_tlv)

    ios_device_pairing_id = ios_pairing_id.encode()
    ios_device_info = ios_device_x + ios_device_pairing_id + ios_device_public_bytes

    ios_device_signature = ios_device_ltsk.sign(ios_device_info)

    sub_tlv = [
        (TLV.kTLVType_Identifier, ios_device_pairing_id),
        (TLV.kTLVType_PublicKey, ios_device_public_bytes),
        (TLV.kTLVType_Signature, ios_device_signature),
    ]
    sub_tlv_b = TLV.encode_list(sub_tlv)

    # taking tge iOSDeviceX as key was reversed from
    # https://github.com/KhaosT/HAP-NodeJS/blob/2ea9d761d9bd7593dd1949fec621ab085af5e567/lib/HAPServer.js
    # function handlePairStepFive calling encryption.encryptAndSeal
    encrypted_data_with_auth_tag = ChaCha20Poly1305Encryptor(session_key).encrypt(
        b"", NONCE_PADDING + b"PS-Msg05", bytes(sub_tlv_b)
    )

    response_tlv = [
        (TLV.kTLVType_State, TLV.M5),
        (TLV.kTLVType_EncryptedData, encrypted_data_with_auth_tag),
    ]

    step6_expectations = [
        TLV.kTLVType_State,
        TLV.kTLVType_Error,
        TLV.kTLVType_EncryptedData,
    ]
    response_tlv = yield (response_tlv, step6_expectations)

    #
    # Step #7 ios (Verification) (page 47)
    #
    response_tlv = dict(response_tlv)
    handle_state_step(response_tlv, TLV.M6)

    if TLV.kTLVType_EncryptedData not in response_tlv:
        raise InvalidError("M6: Encrypted data not sent be accessory")

    decrypted_data = ChaCha20Poly1305Decryptor(session_key).decrypt(
        b"",
        NONCE_PADDING + b"PS-Msg06",
        bytes(response_tlv[TLV.kTLVType_EncryptedData]),
    )
    if decrypted_data is False:
        raise IllegalData("step 7")

    response_tlv = TLV.decode_bytearray(bytearray(decrypted_data))
    response_tlv = dict(response_tlv)

    if TLV.kTLVType_Signature not in response_tlv:
        raise InvalidError("Accessory did not send signature")

    if TLV.kTLVType_Identifier not in response_tlv:
        raise InvalidError("Accessory did not send identifier")

    if TLV.kTLVType_PublicKey not in response_tlv:
        raise InvalidError("Accessory did not send public key")

    accessory_ltpk = response_tlv[TLV.kTLVType_PublicKey]
    accessory_pairing_id = response_tlv[TLV.kTLVType_Identifier]
    accessory_sig = response_tlv[TLV.kTLVType_Signature]
    session_key_bytes = srp_client.get_session_key_bytes()

    accessory_x = hkdf_derive(
        session_key_bytes,
        b"Pair-Setup-Accessory-Sign-Salt",
        b"Pair-Setup-Accessory-Sign-Info",
    )

    accessory_info = accessory_x + accessory_pairing_id + accessory_ltpk

    e25519s = ed25519.Ed25519PublicKey.from_public_bytes(bytes(accessory_ltpk))
    try:
        e25519s.verify(bytes(accessory_sig), bytes(accessory_info))
    except cryptography_exceptions.InvalidSignature:
        raise InvalidSignatureError("step #7")

    ios_device_ltsk_private_bytes = ios_device_ltsk.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )

    return {
        "AccessoryPairingID": accessory_pairing_id.decode(),
        "AccessoryLTPK": hexlify(accessory_ltpk).decode(),
        "iOSPairingId": ios_pairing_id,
        "iOSDeviceLTSK": ios_device_ltsk_private_bytes.hex(),
        "iOSDeviceLTPK": ios_device_public_bytes.hex(),
    }


def resume_m1(
    session_id: bytes, pub_key: bytes, derive: Callable[[bytes, bytes], bytes]
) -> list[tuple[int, bytes]]:
    request_key = derive(
        pub_key + session_id,
        b"Pair-Resume-Request-Info",
    )

    logger.debug("resume request key: %s", request_key)

    key = ChaCha20Poly1305Encryptor(request_key)

    auth_tag = key.encrypt(
        b"",
        NONCE_PADDING + b"PR-Msg01",
        b"",
    )

    logger.debug("auth tag: %s", auth_tag)

    return [
        (TLV.kTLVType_State, TLV.M1),
        (TLV.kTLVType_Method, TLV.kTLVMethod_Resume.to_bytes(1, "little")),
        (TLV.kTLVType_PublicKey, pub_key),
        (TLV.kTLVType_SessionID, session_id),
        (TLV.kTLVType_EncryptedData, auth_tag),
    ]


def resume_m3(
    pub_key: bytes, derive: Callable[[bytes, bytes], bytes], response: dict[int, bytes]
) -> Callable[[bytes, bytes], bytes] | None:
    if not (method := response.get(TLV.kTLVType_Method)):
        logger.debug("M3: Failure to resume existing session: Method not present")
        return None

    if int.from_bytes(method, "little") != TLV.kTLVMethod_Resume:
        logger.debug("M3: Failure to resume existing session: Method != Resume")
        return None

    if not (session_id := response.get(TLV.kTLVType_SessionID)):
        logger.debug("M3: Failure to resume existing session: No session id present")
        return None

    if not (auth_tag := response.get(TLV.kTLVType_EncryptedData)):
        logger.debug("M3: Failure to resume existing session: No auth tag present")
        return None

    response_key = derive(
        pub_key + session_id,
        b"Pair-Resume-Response-Info",
    )

    key = ChaCha20Poly1305Decryptor(response_key)
    plaintext = key.decrypt(
        b"",
        NONCE_PADDING + b"PR-Msg02",
        bytes(auth_tag),
    )

    if plaintext != b"":
        logger.debug(
            "M3: Failure to resume existing session: Could not decrypt kTLVType_EncryptedData"
        )
        return None

    shared_secret = derive(
        pub_key + session_id,
        b"Pair-Resume-Shared-Secret-Info",
    )

    def derive(salt: bytes, info: bytes, length: int = 32) -> bytes:
        return hkdf_derive(shared_secret, salt, info, length=length)

    logger.debug("M3: Resume exchange success")

    return session_id, derive


def get_session_keys(
    pairing_data: dict[str, str | int | list[Any]],
    session_id=None,
    derive=None,
) -> Generator[
    (
        tuple[list[tuple[int, bytearray] | tuple[int, bytes]], list[int]]
        | tuple[list[tuple[int, bytearray]], list[int]]
    ),
    None,
    Callable[[str, str], bytes],
]:
    """
    HomeKit Controller state machine to perform a pair verify operation as described in chapter 4.8 page 47 ff.
    :param pairing_data: the paring data as returned by perform_pair_setup
    :return: tuple of the session keys (controller_to_accessory_key and  accessory_to_controller_key)
    :raises InvalidAuthTagError: if the auth tag could not be verified,
    :raises IncorrectPairingIdError: if the accessory's LTPK could not be found
    :raises InvalidSignatureError: if the accessory's signature could not be verified
    :raises AuthenticationError: if the secured session could not be established
    """

    #
    # Step #1 ios --> accessory (send verify start Request) (page 47)
    #
    ios_key = x25519.X25519PrivateKey.generate()
    ios_key_pub = ios_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw
    )

    request_tlv = [(TLV.kTLVType_State, TLV.M1), (TLV.kTLVType_PublicKey, ios_key_pub)]

    # If session_id is provided we can request that the accessory resumes it
    if session_id and derive:
        request_tlv = resume_m1(session_id, ios_key_pub, derive)

    step2_expectations = [
        TLV.kTLVType_State,
        TLV.kTLVType_PublicKey,
        TLV.kTLVType_EncryptedData,
    ]
    response_tlv = yield (request_tlv, step2_expectations)

    #
    # Step #3 ios --> accessory (send SRP verify request)  (page 49)
    #
    response_tlv = dict(response_tlv)
    handle_state_step(response_tlv, TLV.M2)

    # Check for kTLVMethod_Resume - we might be able to shortcut the pair-verify
    if derive and (response := resume_m3(ios_key_pub, derive, response_tlv)):
        return response

    if TLV.kTLVType_PublicKey not in response_tlv:
        raise InvalidError("M2: Missing public key")

    if TLV.kTLVType_EncryptedData not in response_tlv:
        raise InvalidError("M2: Missing encrypted data")

    # 1) generate shared secret
    accessorys_session_pub_key_bytes = bytes(response_tlv[TLV.kTLVType_PublicKey])
    accessorys_session_pub_key = x25519.X25519PublicKey.from_public_bytes(
        accessorys_session_pub_key_bytes
    )
    shared_secret = ios_key.exchange(accessorys_session_pub_key)

    # 2) derive session key
    session_key = hkdf_derive(
        shared_secret, b"Pair-Verify-Encrypt-Salt", b"Pair-Verify-Encrypt-Info"
    )

    # 3) verify auth tag on encrypted data and 4) decrypt
    encrypted = response_tlv[TLV.kTLVType_EncryptedData]
    decrypted = ChaCha20Poly1305Decryptor(session_key).decrypt(
        b"", NONCE_PADDING + b"PV-Msg02", bytes(encrypted)
    )
    if type(decrypted) == bool and not decrypted:
        raise InvalidAuthTagError("step 3")
    d1 = dict(TLV.decode_bytes(decrypted))

    if TLV.kTLVType_Identifier not in d1:
        raise InvalidError("M2: Encrypted data did not contain identifier")

    if TLV.kTLVType_Signature not in d1:
        raise InvalidError("M2: Encrypted data did not contain signature")

    # 5) look up pairing by accessory name
    accessory_name = d1[TLV.kTLVType_Identifier].decode()

    if pairing_data["AccessoryPairingID"] != accessory_name:
        raise IncorrectPairingIdError("step 3")

    accessory_ltpk = ed25519.Ed25519PublicKey.from_public_bytes(
        bytes.fromhex(pairing_data["AccessoryLTPK"])
    )

    # 6) verify accessory's signature
    accessory_sig = d1[TLV.kTLVType_Signature]
    accessory_session_pub_key_bytes = response_tlv[TLV.kTLVType_PublicKey]
    accessory_info = (
        accessory_session_pub_key_bytes + accessory_name.encode() + ios_key_pub
    )
    try:
        accessory_ltpk.verify(bytes(accessory_sig), bytes(accessory_info))
    except cryptography_exceptions.InvalidSignature:
        raise InvalidSignatureError("step 3")

    # 7) create iOSDeviceInfo
    ios_device_info = (
        ios_key_pub
        + pairing_data["iOSPairingId"].encode()
        + accessorys_session_pub_key_bytes
    )

    # 8) sign iOSDeviceInfo with long term secret key
    ios_device_ltsk_h = pairing_data["iOSDeviceLTSK"]
    # ios_device_ltpk_h = pairing_data["iOSDeviceLTPK"]

    ios_device_ltsk = ed25519.Ed25519PrivateKey.from_private_bytes(
        bytes.fromhex(ios_device_ltsk_h)
    )
    # ios_device_ltsk = ed25519.SigningKey(
    #    bytes.fromhex(ios_device_ltsk_h) + bytes.fromhex(ios_device_ltpk_h)
    # )
    ios_device_signature = ios_device_ltsk.sign(ios_device_info)

    # 9) construct sub tlv
    sub_tlv = TLV.encode_list(
        [
            (TLV.kTLVType_Identifier, pairing_data["iOSPairingId"].encode()),
            (TLV.kTLVType_Signature, ios_device_signature),
        ]
    )

    # 10) encrypt and sign
    encrypted_data_with_auth_tag = ChaCha20Poly1305Encryptor(session_key).encrypt(
        b"", NONCE_PADDING + b"PV-Msg03", bytes(sub_tlv)
    )

    # 11) create tlv
    request_tlv = [
        (TLV.kTLVType_State, TLV.M3),
        (TLV.kTLVType_EncryptedData, encrypted_data_with_auth_tag),
    ]

    step3_expectations = [TLV.kTLVType_State, TLV.kTLVType_Error]
    response_tlv = yield (request_tlv, step3_expectations)

    #
    #   Post Step #4 verification (page 51)
    #
    response_tlv = dict(response_tlv)
    handle_state_step(response_tlv, TLV.M4)

    # return function to calculate session keys
    def derive(salt: bytes, info: bytes, length: int = 32) -> bytes:
        return hkdf_derive(shared_secret, salt, info, length=length)

    session_id = derive(
        b"Pair-Verify-ResumeSessionID-Salt",
        b"Pair-Verify-ResumeSessionID-Info",
        length=8,
    )

    return session_id, derive
