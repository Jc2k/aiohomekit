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
    calc_r,
    calc_s,
    chacha20_aead_decrypt,
    chacha20_aead_encrypt,
    chacha20_aead_verify_tag,
    chacha20_encrypt,
    clamp,
    poly1305_key_gen,
    poly1305_mac,
)


def test_example2_4_2():
    # Test aus 2.4.2
    k = 0x000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F .to_bytes(
        length=32, byteorder="big"
    )
    n = 0x000000000000004A00000000 .to_bytes(length=12, byteorder="big")
    c = 1
    plain_text = (
        "Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, "
        "sunscreen would be it."
    )
    r = chacha20_encrypt(k, c, n, plain_text.encode())
    r_ = [
        0x6E,
        0x2E,
        0x35,
        0x9A,
        0x25,
        0x68,
        0xF9,
        0x80,
        0x41,
        0xBA,
        0x07,
        0x28,
        0xDD,
        0x0D,
        0x69,
        0x81,
        0xE9,
        0x7E,
        0x7A,
        0xEC,
        0x1D,
        0x43,
        0x60,
        0xC2,
        0x0A,
        0x27,
        0xAF,
        0xCC,
        0xFD,
        0x9F,
        0xAE,
        0x0B,
        0xF9,
        0x1B,
        0x65,
        0xC5,
        0x52,
        0x47,
        0x33,
        0xAB,
        0x8F,
        0x59,
        0x3D,
        0xAB,
        0xCD,
        0x62,
        0xB3,
        0x57,
        0x16,
        0x39,
        0xD6,
        0x24,
        0xE6,
        0x51,
        0x52,
        0xAB,
        0x8F,
        0x53,
        0x0C,
        0x35,
        0x9F,
        0x08,
        0x61,
        0xD8,
        0x07,
        0xCA,
        0x0D,
        0xBF,
        0x50,
        0x0D,
        0x6A,
        0x61,
        0x56,
        0xA3,
        0x8E,
        0x08,
        0x8A,
        0x22,
        0xB6,
        0x5E,
        0x52,
        0xBC,
        0x51,
        0x4D,
        0x16,
        0xCC,
        0xF8,
        0x06,
        0x81,
        0x8C,
        0xE9,
        0x1A,
        0xB7,
        0x79,
        0x37,
        0x36,
        0x5A,
        0xF9,
        0x0B,
        0xBF,
        0x74,
        0xA3,
        0x5B,
        0xE6,
        0xB4,
        0x0B,
        0x8E,
        0xED,
        0xF2,
        0x78,
        0x5E,
        0x42,
        0x87,
        0x4D,
    ]
    r_ = bytearray(r_)
    assert r == r_


def test_example2_5_2():
    # Test aus 2.5.2
    key = 0x85D6BE7857556D337F4452FE42D506A80103808AFB0DB2FD4ABFF6AF4149F51B .to_bytes(
        length=32, byteorder="big"
    )
    text = "Cryptographic Forum Research Group"

    s = calc_s(key)
    assert s == 0x1BF54941AFF6BF4AFDB20DFB8A800301

    r = calc_r(key)
    assert r == 0x85D6BE7857556D337F4452FE42D506A8

    r = clamp(r)
    assert r == 0x806D5400E52447C036D555408BED685

    r = poly1305_mac(text.encode(), key)
    r_ = [
        0xA8,
        0x06,
        0x1D,
        0xC1,
        0x30,
        0x51,
        0x36,
        0xC6,
        0xC2,
        0x2B,
        0x8B,
        0xAF,
        0x0C,
        0x01,
        0x27,
        0xA9,
    ]
    r_ = bytearray(r_)
    assert r == r_


def test_example2_6_2():
    # Test aus 2.6.2
    key = 0x808182838485868788898A8B8C8D8E8F909192939495969798999A9B9C9D9E9F .to_bytes(
        length=32, byteorder="big"
    )
    nonce = 0x000000000001020304050607 .to_bytes(length=12, byteorder="big")
    r_ = [
        0x8A,
        0xD5,
        0xA0,
        0x8B,
        0x90,
        0x5F,
        0x81,
        0xCC,
        0x81,
        0x50,
        0x40,
        0x27,
        0x4A,
        0xB2,
        0x94,
        0x71,
        0xA8,
        0x33,
        0xB6,
        0x37,
        0xE3,
        0xFD,
        0x0D,
        0xA5,
        0x08,
        0xDB,
        0xB8,
        0xE2,
        0xFD,
        0xD1,
        0xA6,
        0x46,
    ]
    r_ = bytes(r_)

    r = poly1305_key_gen(key, nonce)
    assert r == r_


def test_example2_8_2():
    # Test aus 2.8.2
    plain_text = (
        "Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, "
        "sunscreen would be it.".encode()
    )
    aad = 0x50515253C0C1C2C3C4C5C6C7 .to_bytes(length=12, byteorder="big")
    key = 0x808182838485868788898A8B8C8D8E8F909192939495969798999A9B9C9D9E9F .to_bytes(
        length=32, byteorder="big"
    )
    iv = 0x4041424344454647 .to_bytes(length=8, byteorder="big")
    fixed = 0x07000000 .to_bytes(length=4, byteorder="big")
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

    r = chacha20_aead_encrypt(aad, key, iv, fixed, plain_text)
    assert r[:-16] == r_[0], "ciphertext"
    assert r[-16:] == r_[1], "tag"

    assert chacha20_aead_verify_tag(aad, key, iv, fixed, r)
    assert (
        chacha20_aead_verify_tag(aad, key, iv, fixed, r + bytes([0, 1, 2, 3])) is False
    )

    plain_text_ = chacha20_aead_decrypt(aad, key, iv, fixed, r)
    assert plain_text == plain_text_

    assert chacha20_aead_decrypt(aad, key, iv, fixed, r + bytes([0, 1, 2, 3])) is False
