import asyncio
import importlib
from unittest.mock import AsyncMock, patch

import pytest

from aiohomekit.controller import Controller, controller as controller_module
from aiohomekit.controller.abstract import TransportType
from aiohomekit.controller.ble.controller import BleController
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


async def test_ble_transport_registered_when_supported() -> None:
    """Test the BLE transport starts with an internally constructed scanner."""
    scanner = AsyncMock()
    with (
        patch.object(controller_module, "BLE_TRANSPORT_SUPPORTED", True),
        patch.object(controller_module, "COAP_TRANSPORT_SUPPORTED", False),
        patch.object(controller_module, "IP_TRANSPORT_SUPPORTED", False),
        patch("aiohomekit.controller.ble.controller.BleakScanner", return_value=scanner),
    ):
        controller = Controller()
        await controller.async_start()

    assert len(controller.transports) == 1
    assert isinstance(controller.transports[TransportType.BLE], BleController)
    scanner.start.assert_awaited_once()


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


async def test_coap_backend_imported_in_executor() -> None:
    """The CoAP backend is imported off the event loop, since its import touches the disk."""
    loop = asyncio.get_running_loop()
    with (
        patch.object(controller_module, "BLE_TRANSPORT_SUPPORTED", False),
        patch.object(controller_module, "COAP_TRANSPORT_SUPPORTED", True),
        patch.object(controller_module, "IP_TRANSPORT_SUPPORTED", False),
        patch.object(Controller, "_async_register_backend", AsyncMock()),
        patch.object(loop, "run_in_executor", wraps=loop.run_in_executor) as run_in_executor,
    ):
        await Controller().async_start()

    run_in_executor.assert_called_once_with(
        None, importlib.import_module, "aiohomekit.controller.coap.controller"
    )
