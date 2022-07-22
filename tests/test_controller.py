from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from aiohomekit.controller import controller as controller_module
from aiohomekit.controller import Controller
from aiohomekit.exceptions import AuthenticationError
from aiohomekit.controller.ble.controller import BleController
from aiohomekit.controller.ip.controller import IpController

async def test_remove_pairing(controller_and_paired_accessory):
    pairing = controller_and_paired_accessory.aliases["alias"]

    # Verify that there is a pairing connected and working
    await pairing.get_characteristics([(1, 9)])

    # Remove pairing from controller
    await controller_and_paired_accessory.remove_pairing("alias")

    # Verify now gives an appropriate error
    with pytest.raises(AuthenticationError):
        await pairing.get_characteristics([(1, 9)])


async def test_passing_in_bleak_to_controller():
    """Test we can pass in a bleak scanner instance to the controller.

    Passing in the instance should enable BLE scanning.
    """
    with patch.object(
        controller_module, "BLE_TRANSPORT_SUPPORTED", False
    ), patch.object(controller_module, "COAP_TRANSPORT_SUPPORTED", False), patch.object(
        controller_module, "IP_TRANSPORT_SUPPORTED", False
    ):
        controller = Controller(bleak_scanner_instance=AsyncMock(register_detection_callback=MagicMock()))
        await controller.async_start()

    assert len(controller._transports) == 1
    assert isinstance(controller._transports[0], BleController)


async def test_passing_in_async_zeroconf():
    """Test we can pass in a zeroconf ServiceBrowser instance to the controller.

    Passing in the instance should enable zeroconf scanning.
    """
    with patch.object(
        controller_module, "BLE_TRANSPORT_SUPPORTED", False
    ), patch.object(controller_module, "COAP_TRANSPORT_SUPPORTED", False), patch.object(
        controller_module, "IP_TRANSPORT_SUPPORTED", False
    ):
        controller = Controller(async_zeroconf_instance=AsyncMock())
        await controller.async_start()

    assert len(controller._transports) == 1
    assert isinstance(controller._transports[0], IpController)
