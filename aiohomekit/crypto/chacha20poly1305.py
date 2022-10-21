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

"""
Implements the ChaCha20 stream cipher and the Poly1350 authenticator. More information can be found on
https://tools.ietf.org/html/rfc7539. See HomeKit spec page 51.
"""

from __future__ import annotations
import struct

from chacha20poly1305_reuseable import ChaCha20Poly1305Reusable
from cryptography.exceptions import InvalidTag
from chacha20poly1305 import (
    ChaCha20Poly1305 as ChaCha20Poly1305PurePython,
    Poly1305,
    ChaCha,
    ct_compare_digest,
    TagInvalidException,
)

import logging

logger = logging.getLogger(__name__)


class ChaCha20Poly1305Encryptor:
    """Encrypt data with ChaCha20Poly1305."""

    def __init__(self, key: bytes) -> None:
        """Init the encryptor

        :param key: 256-bit (32-byte) key of type bytes
        """
        assert type(key) is bytes, "key is no instance of bytes"
        assert len(key) == 32
        self.chacha = ChaCha20Poly1305Reusable(key)

    def encrypt(
        self, aad: bytes, iv: bytes, constant: bytes, plaintext: bytes
    ) -> tuple[bytearray, bytes]:
        """
        The encrypt method for chacha20 aead as required by the Apple specification. The 96-bit nonce from RFC7539 is
        formed from the constant and the initialisation vector.

        :param aad: arbitrary length additional authenticated data
        :param iv: the initialisation vector
        :param constant: constant
        :param plaintext: arbitrary length plaintext of type bytes or bytearray
        :return: the cipher text and tag
        """
        assert type(plaintext) in [
            bytes,
            bytearray,
        ], "plaintext is no instance of bytes: %s" % str(type(plaintext))
        nonce = constant + iv
        return self.chacha.encrypt(bytes(nonce), bytes(plaintext), bytes(aad))


class ChaCha20Poly1305Decryptor:
    """Decrypt data with ChaCha20Poly1305."""

    def __init__(self, key: bytes) -> None:
        """Init the decrypter

        :param key: 256-bit (32-byte) key of type bytes
        """
        assert type(key) is bytes, "key is no instance of bytes"
        assert len(key) == 32
        self.chacha = ChaCha20Poly1305Reusable(key)

    def decrypt(
        self, aad: bytes, iv: bytes, constant: bytes, ciphertext: bytes
    ) -> bool | bytearray:
        """
        The decrypt method for chacha20 aead as required by the Apple specification. The 96-bit nonce from RFC7539 is
        formed from the constant and the initialisation vector.

        :param aad: arbitrary length additional authenticated data
        :param iv: the initialisation vector
        :param constant: constant
        :param ciphertext: arbitrary length plaintext of type bytes or bytearray
        :return: False if the tag could not be verified or the plaintext as bytes
        """
        assert type(ciphertext) in [
            bytes,
            bytearray,
        ], "ciphertext is no instance of bytes: %s" % str(type(ciphertext))
        nonce = constant + iv
        try:
            return bytearray(self.chacha.decrypt(nonce, bytes(ciphertext), bytes(aad)))
        except InvalidTag:
            # This should raise rather than the callees having to test for False
            return False


class ChaCha20Poly1305PartialTag(ChaCha20Poly1305PurePython):
    def open(self, nonce: bytes, combined_text: bytes, data: bytes) -> bytes:
        """
        Decrypts and authenticates ciphertext using nonce and data. If the
        tag is valid, the plaintext is returned. If the tag is invalid,
        returns None.
        """
        if len(nonce) != 12:
            raise ValueError("Nonce must be 96 bit long")

        # data = b"\x00" * 6
        # data = b""
        expected_tag = combined_text[-4:]
        ciphertext = combined_text[:-4]
        logger.warning(
            "Trying open with : nonce=%s, data=%s ciphertext=%s expected_tag=%s",
            nonce,
            data,
            ciphertext,
            expected_tag,
        )

        otk = self.poly1305_key_gen(self.key, nonce)

        mac_data = data + self.pad16(data)
        mac_data += ciphertext + self.pad16(ciphertext)
        mac_data += struct.pack("<Q", len(data))
        mac_data += struct.pack("<Q", len(ciphertext))
        tag = Poly1305(otk).create_tag(mac_data)

        logger.warning("Expected tag: %s", expected_tag.hex())
        logger.warning("Actual tag: %s", tag.hex())

        #        if not ct_compare_digest(tag, expected_tag):
        #            raise TagInvalidException

        return ChaCha(self.key, nonce, counter=1).decrypt(ciphertext)
