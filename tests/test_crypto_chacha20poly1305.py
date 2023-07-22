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

from aiohomekit.crypto.chacha20poly1305 import (
    ChaCha20Poly1305Decryptor,
    ChaCha20Poly1305Encryptor,
    PACK_NONCE,
    NONCE_PADDING,
    DecryptionError,
)
import pytest


def test_example2_8_2():
    # Test aus 2.8.2
    plain_text = (
        b"Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, "
        b"sunscreen would be it."
    )
    aad = 0x50515253C0C1C2C3C4C5C6C7.to_bytes(length=12, byteorder="big")
    key = 0x808182838485868788898A8B8C8D8E8F909192939495969798999A9B9C9D9E9F.to_bytes(
        length=32, byteorder="big"
    )
    iv = 0x4041424344454647.to_bytes(length=8, byteorder="big")
    fixed = 0x07000000.to_bytes(length=4, byteorder="big")
    r_ = (
        bytes(
            [
                0xD3,
                0x1A,
                0x8D,
                0x34,
                0x64,
                0x8E,
                0x60,
                0xDB,
                0x7B,
                0x86,
                0xAF,
                0xBC,
                0x53,
                0xEF,
                0x7E,
                0xC2,
                0xA4,
                0xAD,
                0xED,
                0x51,
                0x29,
                0x6E,
                0x08,
                0xFE,
                0xA9,
                0xE2,
                0xB5,
                0xA7,
                0x36,
                0xEE,
                0x62,
                0xD6,
                0x3D,
                0xBE,
                0xA4,
                0x5E,
                0x8C,
                0xA9,
                0x67,
                0x12,
                0x82,
                0xFA,
                0xFB,
                0x69,
                0xDA,
                0x92,
                0x72,
                0x8B,
                0x1A,
                0x71,
                0xDE,
                0x0A,
                0x9E,
                0x06,
                0x0B,
                0x29,
                0x05,
                0xD6,
                0xA5,
                0xB6,
                0x7E,
                0xCD,
                0x3B,
                0x36,
                0x92,
                0xDD,
                0xBD,
                0x7F,
                0x2D,
                0x77,
                0x8B,
                0x8C,
                0x98,
                0x03,
                0xAE,
                0xE3,
                0x28,
                0x09,
                0x1B,
                0x58,
                0xFA,
                0xB3,
                0x24,
                0xE4,
                0xFA,
                0xD6,
                0x75,
                0x94,
                0x55,
                0x85,
                0x80,
                0x8B,
                0x48,
                0x31,
                0xD7,
                0xBC,
                0x3F,
                0xF4,
                0xDE,
                0xF0,
                0x8E,
                0x4B,
                0x7A,
                0x9D,
                0xE5,
                0x76,
                0xD2,
                0x65,
                0x86,
                0xCE,
                0xC6,
                0x4B,
                0x61,
                0x16,
            ]
        ),
        bytes(
            [
                0x1A,
                0xE1,
                0x0B,
                0x59,
                0x4F,
                0x09,
                0xE2,
                0x6A,
                0x7E,
                0x90,
                0x2E,
                0xCB,
                0xD0,
                0x60,
                0x06,
                0x91,
            ]
        ),
    )
    nonce = fixed + iv
    r = ChaCha20Poly1305Encryptor(key).encrypt(aad, nonce, plain_text)
    assert r[:-16] == r_[0], "ciphertext"
    assert r[-16:] == r_[1], "tag"

    plain_text_ = ChaCha20Poly1305Decryptor(key).decrypt(aad, nonce, r)
    assert plain_text == plain_text_

    with pytest.raises(DecryptionError):
        ChaCha20Poly1305Decryptor(key).decrypt(aad, nonce, r + bytes([0, 1, 2, 3]))
