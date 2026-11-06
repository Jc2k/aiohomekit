"""Tests for the test accessory server helpers in conftest."""

import errno
import os
import socket
import tempfile
from unittest.mock import MagicMock, patch

import pytest

from tests.conftest import ensure_server_bound, next_available_port, port_ready


def _listening_socket(port: int) -> socket.socket:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(("127.0.0.1", port))
    sock.listen()
    return sock


def test_port_ready_detects_listening_port() -> None:
    port = next_available_port()
    assert port_ready(port) is False
    with _listening_socket(port):
        assert port_ready(port) is True


def test_port_ready_reraises_unexpected_bind_errors() -> None:
    with (
        patch.object(socket.socket, "bind", side_effect=OSError(errno.EADDRNOTAVAIL, "nope")),
        pytest.raises(OSError) as exc_info,
    ):
        port_ready(next_available_port())
    assert exc_info.value.errno == errno.EADDRNOTAVAIL


def test_ensure_server_bound_passes_when_bound() -> None:
    port = next_available_port()
    httpd = MagicMock()
    with _listening_socket(port):
        ensure_server_bound(httpd, port, "/nonexistent")
    httpd.server_close.assert_not_called()


def test_ensure_server_bound_cleans_up_when_not_bound() -> None:
    port = next_available_port()
    httpd = MagicMock()
    with tempfile.NamedTemporaryFile(delete=False) as config_file:
        config_path = config_file.name
    with pytest.raises(RuntimeError, match=f"did not bind port {port}"):
        ensure_server_bound(httpd, port, config_path)
    httpd.server_close.assert_called_once_with()
    assert not os.path.exists(config_path)
