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

from aiohomekit.crypto.srp import SrpClient, SrpServer, pad_left, to_byte_array


class ZeroSaltSrpServer(SrpServer):
    def _create_salt(self):
        return b"\x00" * 16


@pytest.mark.parametrize("cls", [ZeroSaltSrpServer, SrpServer])
def test_1(cls):
    # step M1

    # step M2
    setup_code = "123-45-678"  # transmitted on second channel
    server = cls("Pair-Setup", setup_code)
    server_pub_key = server.get_public_key()
    server_salt = server.get_salt()

    # step M3
    client = SrpClient("Pair-Setup", setup_code)
    client.set_salt(server_salt)
    client.set_server_public_key(server_pub_key)

    client_pub_key = client.get_public_key()
    clients_proof = client.get_proof()

    # step M4
    server.set_client_public_key(client_pub_key)
    server.get_shared_secret()
    assert server.verify_clients_proof(clients_proof) is True
    servers_proof = server.get_proof(clients_proof)

    # step M5
    assert client.verify_servers_proof(servers_proof) is True
