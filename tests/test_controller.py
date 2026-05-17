from unittest.mock import patch

import pytest

from aiohomekit.controller import Controller, controller as controller_module
from aiohomekit.controller.abstract import TransportType
from aiohomekit.controller.ip.controller import IpController
from aiohomekit.exceptions import AccessoryDisconnectedError


async def test_remove_pairing(controller_and_paired_accessory):
    pairing = controller_and_paired_accessory.aliases["alias"]

    # Verify that there is a pairing connected and working
    await pairing.get_characteristics([(1, 9)])

    # Remove pairing from controller
    await controller_and_paired_accessory.remove_pairing("alias")

    # Verify now gives an appropriate error
    with pytest.raises(AccessoryDisconnectedError):
        await pairing.get_characteristics([(1, 9)])


async def test_passing_in_async_zeroconf(mock_asynczeroconf):
    """Test we can pass in a zeroconf ServiceBrowser instance to the controller.

    Passing in the instance should enable zeroconf scanning.
    """
    with (
        patch.object(controller_module, "BLE_TRANSPORT_SUPPORTED", False),
        patch.object(controller_module, "COAP_TRANSPORT_SUPPORTED", False),
        patch.object(controller_module, "IP_TRANSPORT_SUPPORTED", False),
    ):
        controller = Controller(async_zeroconf_instance=mock_asynczeroconf)
        await controller.async_start()

    assert len(controller.transports) == 1
    assert isinstance(controller.transports[TransportType.IP], IpController)
