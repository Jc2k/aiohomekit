"""Test status codes."""

from aiohomekit.protocol.statuscodes import HapStatusCodes


async def test_normalized_statuscodes():
    """Verify we account for quirks in HAP implementations."""
    assert HapStatusCodes[-70411] == "Insufficient Authorization."
    assert HapStatusCodes[70411] == "Insufficient Authorization."
