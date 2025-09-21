from __future__ import annotations

import pytest

from aiohomekit.controller.ble.manufacturer_data import HomeKitAdvertisement


def test_manufacturer_data_too_short() -> None:
    """Test that short manufacturer data raises appropriate error."""
    # Valid HomeKit advertisement type but buffer too short (less than 15 bytes)
    short_data = b"\x06\x00\x00\x01\x02\x03\x04\x05\x06"  # Only 9 bytes

    with pytest.raises(ValueError, match="HomeKit advertisement data too short"):
        HomeKitAdvertisement.from_manufacturer_data(
            name="Test", address="00:00:00:00:00:00", manufacturer_data={76: short_data}
        )


def test_manufacturer_data_without_setup_hash() -> None:
    """Test with 15 bytes (no setup hash - valid for older devices)."""
    data_no_hash = b"\x06\x00\x00\x01\x02\x03\x04\x05\x06\x07\x08\x00\x00\x00\x00"  # 15 bytes total

    result = HomeKitAdvertisement.from_manufacturer_data(
        name="Test", address="00:00:00:00:00:00", manufacturer_data={76: data_no_hash}
    )

    assert result is not None
    assert result.address == "00:00:00:00:00:00"
    assert result.name == "Test"
    assert result.setup_hash == b""  # No setup hash


def test_manufacturer_data_with_setup_hash() -> None:
    """Test with exactly 19 bytes (includes setup hash)."""
    valid_data = (
        b"\x06\x00\x00\x01\x02\x03\x04\x05\x06\x07\x08\x00\x00\x00\x00\x00\x11\x22\x33"  # 19 bytes total
    )

    result = HomeKitAdvertisement.from_manufacturer_data(
        name="Test", address="00:00:00:00:00:00", manufacturer_data={76: valid_data}
    )

    assert result is not None
    assert result.address == "00:00:00:00:00:00"
    assert result.name == "Test"
    assert result.setup_hash == b"\x00\x11\x22\x33"  # Has setup hash
