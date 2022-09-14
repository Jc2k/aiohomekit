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
Implements the Secure Remote Password (SRP) algorithm. More information can be found on
https://tools.ietf.org/html/rfc5054. See HomeKit spec page 36 for adjustments imposed by Apple.
"""
from __future__ import annotations

from collections.abc import Iterable
import hashlib
import math
import os

# The K value for HK SRP is always the same because G and N are fixed
CLIENT_K_VALUE = int(
    b"a9c2e2559bf0ebb53f0cbbf62282906bede7f2182f00678211fbd5bde5b285033a4993503b87397f9be5ec02080fedbc0835587ad039060879b8621e8c3659e0",
    16,
)

# generator as defined by 3072bit group of RFC 5054
GENERATOR_VALUE = int(b"5", 16)

HK_KEY_LENGTH = 384

# modulus as defined by 3072bit group of RFC 5054
MODULUS_VALUE = int(
    b"""\
FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E08\
8A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B\
302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9\
A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE6\
49286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8\
FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D\
670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C\
180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF695581718\
3995497CEA956AE515D2261898FA051015728E5A8AAAC42DAD33170D\
04507A33A85521ABDF1CBA64ECFB850458DBEF0A8AEA71575D060C7D\
B3970F85A6E1E4C7ABF5AE8CDB0933D71E8C94E04A25619DCEE3D226\
1AD2EE6BF12FFA06D98A0864D87602733EC86A64521F2B18177B200C\
BBE117577A615D6C770988C0BAD946E208E24FA074E5AB3143DB5BFC\
E0FD108E4B82D120A93AD2CAFFFFFFFFFFFFFFFF""",
    16,
)


def pad_left(data: bytes, length: int) -> bytes:
    """Pads the data with 0x00 until it is of length length.

    Some devices use a salt of all 0s (LIFX BEAM)
    """
    return bytes(length - len(data)) + data


def to_byte_array(num: int) -> bytearray:
    return bytearray(num.to_bytes(int(math.ceil(num.bit_length() / 8)), "big"))


HASH_MOD = hashlib.sha512(to_byte_array(MODULUS_VALUE)).digest()  # H(modulus)
HASH_GEN = hashlib.sha512(to_byte_array(GENERATOR_VALUE)).digest()  # H(generator)
H_GROUP = bytes(
    HASH_MOD[i] ^ HASH_GEN[i] for i in range(0, len(HASH_MOD))
)  # H(modulus) xor H(generator)


class Srp:
    """HomeKit SRP implementation."""

    def __init__(self, username: str, password: str) -> None:
        self.g = GENERATOR_VALUE  # generator
        self.n = MODULUS_VALUE  # modulus
        self.hGroup = H_GROUP
        # HomeKit requires SHA-512 (See page 36)
        self.h = hashlib.sha512
        self.A: int | None = None  # client's public key
        self.B: int | None = None  # server's public key
        self.salt: int | None = None  # salt as defined by RFC 5054
        self.salt_b: bytearray | None = None  # salt as bytes
        self.A_b: bytearray | None = None  # client's public key as bytes
        self.B_b: bytearray | None = None  # server's public key as bytes
        self.username = username
        self.password = password
        self.hu = self.digest(self.username.encode())  # H(username)
        self._session_key: bytes | None = None  # session key

    @staticmethod
    def generate_private_key() -> int:
        """
        Static function to generate a 16 byte random key.

        :return: the key as an integer
        """
        return int.from_bytes(os.urandom(16), byteorder="big")

    def digest(self, *data: Iterable[bytes]) -> bytes:
        return self.h(b"".join(data)).digest()

    def _calculate_k(self) -> int:
        """This value is static and never changes since n and g never change."""
        return CLIENT_K_VALUE

    def _calculate_u(self) -> int:
        """Returns the U value."""
        self._assert_public_keys()
        return int.from_bytes(self.digest(self.A_b, self.B_b), "big")

    def get_shared_secret_bytes(self) -> bytes:
        """Returns the shared secret as bytes."""
        return pad_left(Srp.to_byte_array(self.get_shared_secret()), HK_KEY_LENGTH)

    def get_session_key_bytes(self) -> bytes:
        """Returns the session key as bytes."""
        if self._session_key is not None:
            return self._session_key
        self._session_key = self.digest(self.get_shared_secret_bytes())
        return self._session_key

    def get_session_key(self) -> int:
        """Return the K value for the session key."""
        return int.from_bytes(self.get_session_key_bytes(), "big")

    @staticmethod
    def to_byte_array(num: int) -> bytearray:
        return to_byte_array(num)

    def _calculate_client_password_x(self) -> int:
        """Calculate the x value for the client's password."""
        return int.from_bytes(
            self.digest(
                self.salt_b,
                self.digest(f"{self.username}:{self.password}".encode()),
            ),
            "big",
        )

    def get_shared_secret(self):
        raise NotImplementedError()

    def _assert_public_keys(self) -> None:
        if self.A_b is None:
            raise RuntimeError("Client's public key is missing")
        if self.B_b is None:
            raise RuntimeError("Servers's public key is missing")


class SrpClient(Srp):
    """
    Implements all functions that are required to simulate an iOS HomeKit controller
    """

    def __init__(self, username: str, password: str) -> None:
        super().__init__(username, password)
        self.a = self.generate_private_key()  # client's private key
        self.A = pow(self.g, self.a, self.n)  # public key
        self.A_b = pad_left(to_byte_array(self.A), HK_KEY_LENGTH)  # public key as bytes
        self.k = self._calculate_k()  # static k value

    def set_salt(self, salt: int | bytearray) -> None:
        if isinstance(salt, bytearray):
            self.salt = int.from_bytes(salt, "big")
        else:
            self.salt = salt

        self.salt_b = pad_left(to_byte_array(self.salt), 16)
        self.x = self._calculate_client_password_x()

    def get_public_key(self) -> int:
        return self.A

    def get_public_key_bytes(self) -> bytes:
        return self.A_b

    def set_server_public_key(self, B_b: bytearray | bytes) -> None:
        assert isinstance(B_b, (bytes, bytearray)), "The public key must be a bytes"
        self.B_b = B_b
        self.B = int.from_bytes(B_b, "big")

    def get_shared_secret(self) -> int:
        if self.B is None:
            raise RuntimeError("Server's public key is missing")
        u = self._calculate_u()
        v = pow(self.g, self.x, self.n)
        tmp1 = self.B - (self.k * v)
        tmp2 = self.a + (u * self.x)  # % self.n
        S = pow(tmp1, tmp2, self.n)
        return S

    def get_proof(self) -> int:
        """Get the proof/M value."""
        return int.from_bytes(self.get_proof_bytes(), "big")

    def get_proof_bytes(self) -> bytes:
        """Get the proof/M value."""
        self._assert_public_keys()
        assert self.username is not None
        K = self.get_session_key_bytes()  # Session Key
        return self.digest(
            self.hGroup,
            self.hu,
            self.salt_b,
            self.A_b,
            self.B_b,
            K,
        )

    def verify_servers_proof_bytes(self, M_b: bytes) -> bool:
        """Verify the proof/M value."""
        return self.verify_servers_proof(int.from_bytes(M_b, "big"))

    def verify_servers_proof(self, M: int) -> bool:
        return M == int.from_bytes(
            self.digest(
                self.A_b,
                self.get_proof_bytes(),
                self.get_session_key_bytes(),
            ),
            "big",
        )


class SrpServer(Srp):
    """
    Implements all functions that are required to simulate an iOS HomeKit accessory
    """

    def __init__(self, username: str, password: str) -> None:
        super().__init__(username, password)
        self.salt_b = self._create_salt_bytes()
        self.salt = int.from_bytes(self.salt_b, "big")
        self.verifier = self._get_verifier()
        self.b = self.generate_private_key()
        k = self._calculate_k()
        g_b = pow(self.g, self.b, self.n)
        self.B = (k * self.verifier + g_b) % self.n
        self.B_b = pad_left(to_byte_array(self.B), HK_KEY_LENGTH)  # public key as bytes
        self.A = None

    def _create_salt_bytes(self) -> bytes:
        # generate random salt
        return os.urandom(16)

    def _get_verifier(self) -> int:
        hash_value = self._calculate_client_password_x()
        v = pow(self.g, hash_value, self.n)
        return v

    def set_client_public_key(self, pub_key: int | bytes | bytearray) -> None:
        if isinstance(pub_key, int):
            self.A = pub_key
            self.A_b = pad_left(to_byte_array(self.A), HK_KEY_LENGTH)
        else:
            self.A_b = pub_key
            self.A = int.from_bytes(pub_key, "big")

    def get_salt(self) -> int:
        return self.salt

    def get_public_key(self) -> int:
        k = self._calculate_k()
        return (k * self.verifier + pow(self.g, self.b, self.n)) % self.n

    def get_public_key_bytes(self) -> bytes:
        return pad_left(to_byte_array(self.get_public_key()), HK_KEY_LENGTH)

    def get_shared_secret(self) -> int:
        self._assert_public_keys()
        tmp1 = self.A * pow(self.verifier, self._calculate_u(), self.n)
        return pow(tmp1, self.b, self.n)

    def verify_clients_proof_bytes(self, m: bytes) -> bool:
        return self.verify_clients_proof(int.from_bytes(m, "big"))

    def verify_clients_proof(self, m: int) -> bool:
        self._assert_public_keys()
        K = self.get_session_key_bytes()
        return m == int.from_bytes(
            self.digest(
                self.hGroup,
                self.hu,
                self.salt_b,
                self.A_b,
                self.B_b,
                K,
            ),
            "big",
        )

    def get_proof_bytes(self, m_b: bytes) -> bytes:
        return self.digest(
            self.A_b,
            m_b,
            self.get_session_key_bytes(),
        )

    def get_proof(self, m: int) -> int:
        aligned_client_bytes = pad_left(to_byte_array(m), 64)
        return int.from_bytes(self.get_proof_bytes(aligned_client_bytes), "big")
