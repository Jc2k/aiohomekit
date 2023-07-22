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

from functools import partial
import logging
import struct
from struct import Struct

from chacha20poly1305 import (
    ChaCha,
    ChaCha20Poly1305 as ChaCha20Poly1305PurePython,
    Poly1305,
)
from chacha20poly1305_reuseable import ChaCha20Poly1305Reusable
from cryptography.exceptions import InvalidTag

DecryptionError = InvalidTag

NONCE_PADDING = bytes([0, 0, 0, 0])
PACK_NONCE = partial(Struct("<LQ").pack, 0)


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

    def encrypt(self, aad: bytes, nonce: bytes, plaintext: bytes) -> bytes:
        """
        The encrypt method for chacha20 aead as required by the Apple specification. The 96-bit nonce from RFC7539 is
        formed from the constant and the initialisation vector.

        :param aad: arbitrary length additional authenticated data
        :param iv: the initialisation vector
        :param constant: constant
        :param plaintext: arbitrary length plaintext of type bytes or bytearray
        :return: the cipher text and tag
        """
        return self.chacha.encrypt(nonce, plaintext, aad)


class ChaCha20Poly1305Decryptor:
    """Decrypt data with ChaCha20Poly1305."""

    def __init__(self, key: bytes) -> None:
        """Init the decrypter

        :param key: 256-bit (32-byte) key of type bytes
        """
        assert type(key) is bytes, "key is no instance of bytes"
        assert len(key) == 32
        self.chacha = ChaCha20Poly1305Reusable(key)

    def decrypt(self, aad: bytes, nonce: bytes, ciphertext: bytes) -> bytes:
        """
        The decrypt method for chacha20 aead as required by the Apple specification. The 96-bit nonce from RFC7539 is
        formed from the constant and the initialisation vector.

        :param aad: arbitrary length additional authenticated data
        :param iv: the initialisation vector
        :param constant: constant
        :param ciphertext: arbitrary length plaintext of type bytes or bytearray
        :return: False if the tag could not be verified or the plaintext as bytes
        """
        return self.chacha.decrypt(nonce, ciphertext, aad)


class ChaCha20Poly1305PartialTag(ChaCha20Poly1305PurePython):
    def open(self, nonce: bytes, combined_text: bytes, data: bytes) -> bytes:
        """
        Decrypts and authenticates ciphertext using nonce and data. If the
        tag is valid, the plaintext is returned. If the tag is invalid,
        returns None.

        This decryption only handles ble advertisements, which have a 4 byte
        partial tag.
        """
        if len(nonce) != 12:
            raise ValueError("Nonce must be 96 bit long")

        expected_tag = combined_text[-4:]
        ciphertext = combined_text[:-4]

        otk = self.poly1305_key_gen(self.key, nonce)

        mac_data = data + self.pad16(data)
        mac_data += ciphertext + self.pad16(ciphertext)
        mac_data += struct.pack("<Q", len(data))
        mac_data += struct.pack("<Q", len(ciphertext))
        tag = Poly1305(otk).create_tag(mac_data)

        if not tag.startswith(expected_tag):
            return None
        return ChaCha(self.key, nonce, counter=1).decrypt(ciphertext)
