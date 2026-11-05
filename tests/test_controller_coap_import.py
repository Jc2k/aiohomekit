"""Tests for import-time behaviour of the CoAP controller."""

import subprocess
import sys

_CHECK_PRELOAD = """
import aiocoap.defaults

calls = []
_original = aiocoap.defaults.oscore_missing_modules


def _tracking_oscore_missing_modules():
    calls.append(True)
    return _original()


aiocoap.defaults.oscore_missing_modules = _tracking_oscore_missing_modules

import aiohomekit.controller.coap  # noqa: E402,F401

print(len(calls))
"""


def test_import_runs_aiocoap_transport_selection():
    """aiocoap's optional dependencies are loaded when the module is imported.

    aiocoap imports them lazily (e.g. ``filelock``, which touches the file
    system on import) the first time a context is created. Importing the CoAP
    controller must already have done that, so it does not happen inside the
    event loop later.
    """
    result = subprocess.run(  # noqa: S603
        [sys.executable, "-c", _CHECK_PRELOAD],
        check=True,
        capture_output=True,
        text=True,
    )

    # Once for the client and once for the server transport selection.
    assert result.stdout.strip() == "2"
