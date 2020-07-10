import pytest

from aiohomekit.exceptions import AuthenticationError


async def test_remove_pairing(controller_and_paired_accessory):
    pairing = controller_and_paired_accessory.pairings["alias"]

    # Verify that there is a pairing connected and working
    await pairing.get_characteristics([(1, 9)])

    # Remove pairing from controller
    await controller_and_paired_accessory.remove_pairing("alias")

    # Verify now gives an appropriate error
    with pytest.raises(AuthenticationError):
        await pairing.get_characteristics([(1, 9)])


async def test_find_ip_by_device_id(controller_and_unpaired_accessory):
    ip_discovery = await controller_and_unpaired_accessory.find_ip_by_device_id(
        "12:34:56:00:01:0A", 10
    )

    assert ip_discovery.host == "127.0.0.1"
    assert ip_discovery.device_id == "12:34:56:00:01:0A"
