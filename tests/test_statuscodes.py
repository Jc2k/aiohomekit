"""Test status codes."""

from aiohomekit.protocol.statuscodes import HapStatusCode, to_status_code


async def test_normalized_statuscodes():
    """Verify we account for quirks in HAP implementations."""
    assert to_status_code(70411) == HapStatusCode.INSUFFICIENT_AUTH
    assert to_status_code(-70411) == HapStatusCode.INSUFFICIENT_AUTH
