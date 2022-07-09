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

from chacha20poly1305_reuseable import ChaCha20Poly1305Reusable
from cryptography.exceptions import InvalidTag


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
