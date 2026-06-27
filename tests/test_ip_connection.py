"""Tests for aiohomekit.controller.ip.connection address-fallback behaviour."""

from unittest import mock

import pytest

from aiohomekit.controller.ip.connection import (
    HomeKitConnection,
    SecureHomeKitConnection,
)
from aiohomekit.exceptions import ConnectionError, IncorrectPairingIdError


def _make_secure_connection(hosts: list[str]) -> SecureHomeKitConnection:
    owner = mock.Mock()
    owner.name = "test-device"
    owner.description = None
    pairing_data = {
        "AccessoryIP": hosts[0],
        "AccessoryIPs": hosts,
        "AccessoryPort": 5001,
        "AccessoryPairingID": "correct-pairing-id",
    }
    return SecureHomeKitConnection(owner, pairing_data)


async def test_connect_once_excludes_hosts():
    """exclude_hosts removes addresses before the TCP connection attempt."""
    conn = HomeKitConnection(None, ["1.2.3.13", "1.2.3.10"], 5001)

    seen_hosts: list[str] = []

    def fake_convert(hosts, port):
        seen_hosts.extend(hosts)
        # Return empty so start_connection is never reached; we only care which
        # hosts were passed through.
        return []

    with (
        mock.patch(
            "aiohomekit.controller.ip.connection._convert_hosts_to_addr_infos",
            side_effect=fake_convert,
        ),
        mock.patch(
            "aiohomekit.controller.ip.connection.aiohappyeyeballs.start_connection",
            side_effect=OSError("no addrs"),
        ),
    ):
        with pytest.raises(ConnectionError):
            await conn._connect_once(exclude_hosts=["1.2.3.13"])

    assert seen_hosts == ["1.2.3.10"]


async def test_connect_once_all_hosts_excluded():
    """Excluding every address raises rather than connecting to nothing."""
    conn = HomeKitConnection(None, ["1.2.3.13"], 5001)

    with pytest.raises(ConnectionError):
        await conn._connect_once(exclude_hosts=["1.2.3.13"])


async def test_pair_verify_advances_to_next_address():
    """IncorrectPairingIdError on the first address falls back to the next."""
    conn = _make_secure_connection(["1.2.3.13", "1.2.3.10"])

    tcp_attempts: list[str] = []
    verify_attempts: list[str] = []

    async def fake_tcp_connect(self, exclude_hosts=None):
        exclude_hosts = exclude_hosts or []
        host = next(h for h in self.hosts if h not in exclude_hosts)
        self.connected_host = host
        self.transport = mock.Mock()
        self.protocol = mock.Mock()
        tcp_attempts.append(host)

    async def fake_pair_verify(self):
        verify_attempts.append(self.connected_host)
        # 1.2.3.13 belongs to a different physical device (firmware bug).
        if self.connected_host == "1.2.3.13":
            raise IncorrectPairingIdError("step 3")
        self.is_secure = True

    with (
        mock.patch.object(HomeKitConnection, "_connect_once", fake_tcp_connect),
        mock.patch.object(SecureHomeKitConnection, "_pair_verify", fake_pair_verify),
    ):
        await conn._connect_once()

    assert tcp_attempts == ["1.2.3.13", "1.2.3.10"]
    assert verify_attempts == ["1.2.3.13", "1.2.3.10"]
    assert conn.connected_host == "1.2.3.10"
    assert conn.is_secure is True


async def test_pair_verify_raises_after_all_addresses_exhausted():
    """When every address returns the wrong pairing id the error propagates."""
    conn = _make_secure_connection(["1.2.3.13", "1.2.3.14"])

    verify_attempts: list[str] = []

    async def fake_tcp_connect(self, exclude_hosts=None):
        exclude_hosts = exclude_hosts or []
        host = next(h for h in self.hosts if h not in exclude_hosts)
        self.connected_host = host
        self.transport = mock.Mock()
        self.protocol = mock.Mock()

    async def fake_pair_verify(self):
        verify_attempts.append(self.connected_host)
        raise IncorrectPairingIdError("step 3")

    with (
        mock.patch.object(HomeKitConnection, "_connect_once", fake_tcp_connect),
        mock.patch.object(SecureHomeKitConnection, "_pair_verify", fake_pair_verify),
    ):
        with pytest.raises(IncorrectPairingIdError):
            await conn._connect_once()

    # Both advertised addresses were attempted exactly once before giving up.
    assert verify_attempts == ["1.2.3.13", "1.2.3.14"]
    assert conn.is_secure is False


async def test_pair_verify_raises_when_responding_host_unknown():
    """An unknown/unadvertised responding host propagates without looping."""
    conn = _make_secure_connection(["1.2.3.13"])

    verify_attempts: list[str] = []

    async def fake_tcp_connect(self, exclude_hosts=None):
        # Simulate a responding host that is not one of the advertised hosts
        # (e.g. IPv6 zone-id normalization), so it can never be excluded.
        self.connected_host = "fe80::1%eth0"
        self.transport = mock.Mock()
        self.protocol = mock.Mock()

    async def fake_pair_verify(self):
        verify_attempts.append(self.connected_host)
        raise IncorrectPairingIdError("step 3")

    with (
        mock.patch.object(HomeKitConnection, "_connect_once", fake_tcp_connect),
        mock.patch.object(SecureHomeKitConnection, "_pair_verify", fake_pair_verify),
    ):
        with pytest.raises(IncorrectPairingIdError):
            await conn._connect_once()

    # The error surfaces after a single attempt rather than looping forever.
    assert verify_attempts == ["fe80::1%eth0"]
    assert conn.is_secure is False
