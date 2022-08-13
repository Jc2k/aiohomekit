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
import pytest

from aiohomekit.crypto.srp import SrpClient, SrpServer

# To find short keys
# for _ in range(500000):
#    srp = SrpClient("Pair-Setup", "123-45-789")
#    pub_key_bytes = SrpClient.to_byte_array(srp.A)
#    if len(pub_key_bytes) < 384:
#        pprint.pprint(["found key", srp.a])

class ZeroSaltSrpServer(SrpServer):
    def _create_salt(self):
        return b"\x00" * 16


class LeadingZeroPrivateKeySrpClient(SrpClient):
    def generate_private_key(self):
        return 292137137271783308929690144371568755687


class LeadingZeroPrivateAndPublicKeySrpClient(SrpClient):
    def generate_private_key(self):
        return 70997313118674976963008287637113704817


@pytest.mark.parametrize(
    "server_cls, client_cls",
    [
        (SrpServer, SrpClient),
        (ZeroSaltSrpServer, SrpClient),
        (SrpServer, LeadingZeroPrivateKeySrpClient),
        (SrpServer, LeadingZeroPrivateAndPublicKeySrpClient),
        (ZeroSaltSrpServer, LeadingZeroPrivateAndPublicKeySrpClient),
    ],
)
def test_1(server_cls, client_cls):
    # step M1

    # step M2
    setup_code = "123-45-678"  # transmitted on second channel
    server: SrpServer = server_cls("Pair-Setup", setup_code)
    server_pub_key = server.get_public_key_bytes()
    server_salt = server.get_salt()

    # step M3
    client: SrpClient = client_cls("Pair-Setup", setup_code)
    client.set_salt(server_salt)
    client.set_server_public_key(server_pub_key)

    client_pub_key = client.get_public_key_bytes()
    clients_proof = client.get_proof()

    # step M4
    server.set_client_public_key(client_pub_key)
    server.get_shared_secret()
    assert server.verify_clients_proof(clients_proof) is True
    servers_proof = server.get_proof(clients_proof)

    # step M5
    assert client.verify_servers_proof(servers_proof) is True
