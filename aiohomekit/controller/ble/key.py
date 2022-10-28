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

from aiohomekit.crypto.chacha20poly1305 import (
    ChaCha20Poly1305Decryptor,
    ChaCha20Poly1305Encryptor,
    ChaCha20Poly1305PartialTag,
)


class EncryptionKey:
    def __init__(self, key: bytes):
        self.key = ChaCha20Poly1305Encryptor(key)
        self.counter = 0

    def encrypt(self, data: bytes | bytearray):
        cnt_bytes = self.counter.to_bytes(8, byteorder="little")
        data = self.key.encrypt(b"", cnt_bytes, bytes([0, 0, 0, 0]), data)
        self.counter += 1
        return data


class DecryptionKey:
    def __init__(self, key: bytes):
        self.key = ChaCha20Poly1305Decryptor(key)
        self.counter = 0

    def decrypt(self, data: bytes | bytearray):
        counter = self.counter.to_bytes(8, byteorder="little")

        data = self.key.decrypt(b"", counter, bytes([0, 0, 0, 0]), data)
        self.counter += 1
        return data


class BroadcastDecryptionKey:
    def __init__(self, key: bytes) -> None:
        self.key = ChaCha20Poly1305PartialTag(key)

    def decrypt(
        self, data: bytes | bytearray, gsn: int, advertising_identifier: bytes
    ) -> bytes | bool:
        gsn_bytes = b"\x00\x00\x00\x00" + gsn.to_bytes(8, byteorder="little")
        return self.key.open(gsn_bytes, data, advertising_identifier)
