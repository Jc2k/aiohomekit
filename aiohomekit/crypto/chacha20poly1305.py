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
from typing import Tuple, Union

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305


def chacha20_aead_encrypt(
    aad: bytes, key: bytes, iv: bytes, constant: bytes, plaintext: bytes
) -> Tuple[bytearray, bytes]:
    """
    The encrypt method for chacha20 aead as required by the Apple specification. The 96-bit nonce from RFC7539 is
    formed from the constant and the initialisation vector.

    :param aad: arbitrary length additional authenticated data
    :param key: 256-bit (32-byte) key of type bytes
    :param iv: the initialisation vector
    :param constant: constant
    :param plaintext: arbitrary length plaintext of type bytes or bytearray
    :return: the cipher text and tag
    """
    assert type(plaintext) in [
        bytes,
        bytearray,
    ], "plaintext is no instance of bytes: %s" % str(type(plaintext))
    assert type(key) is bytes, "key is no instance of bytes"
    assert len(key) == 32

    nonce = constant + iv

    chacha = ChaCha20Poly1305(key)
    return chacha.encrypt(bytes(nonce), bytes(plaintext), bytes(aad))


def chacha20_aead_decrypt(
    aad: bytes, key: bytes, iv: bytes, constant: bytes, ciphertext: bytes
) -> Union[bool, bytearray]:
    """
    The decrypt method for chacha20 aead as required by the Apple specification. The 96-bit nonce from RFC7539 is
    formed from the constant and the initialisation vector.

    :param aad: arbitrary length additional authenticated data
    :param key: 256-bit (32-byte) key of type bytes
    :param iv: the initialisation vector
    :param constant: constant
    :param ciphertext: arbitrary length plaintext of type bytes or bytearray
    :return: False if the tag could not be verified or the plaintext as bytes
    """
    assert type(ciphertext) in [
        bytes,
        bytearray,
    ], "ciphertext is no instance of bytes: %s" % str(type(ciphertext))
    assert type(key) is bytes, "key is no instance of bytes"
    assert len(key) == 32

    nonce = constant + iv

    chacha = ChaCha20Poly1305(key)
    try:
        return bytearray(chacha.decrypt(nonce, bytes(ciphertext), bytes(aad)))
    except InvalidTag:
        # This should raise rather than the callees having to test for False
        return False
