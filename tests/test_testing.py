from unittest import mock

from aiohomekit.model import Accessories, Accessory
from aiohomekit.model.characteristics import CharacteristicsTypes
from aiohomekit.model.services import ServicesTypes
from aiohomekit.testing import FakeController


async def test_pairing():
    accessories = Accessories.from_file("tests/fixtures/koogeek_ls1.json")
    controller = FakeController()
    device = controller.add_device(accessories)

    discovery = await controller.find_ip_by_device_id(device.device_id)
    finish_pairing = await discovery.start_pairing("alias")
    pairing = await finish_pairing("111-22-333")

    chars_and_services = await pairing.list_accessories_and_characteristics()
    assert isinstance(chars_and_services, list)


async def test_get_and_set():
    accessories = Accessories.from_file("tests/fixtures/koogeek_ls1.json")
    controller = FakeController()
    device = controller.add_device(accessories)

    discovery = await controller.find_ip_by_device_id(device.device_id)
    finish_pairing = await discovery.start_pairing("alias")
    pairing = await finish_pairing("111-22-333")

    chars = await pairing.get_characteristics([(1, 10)])
    assert chars == {(1, 10): {"value": 0}}

    chars = await pairing.put_characteristics([(1, 10, 1)])
    assert chars == {}

    chars = await pairing.get_characteristics([(1, 10)])
    assert chars == {(1, 10): {"value": 1}}


async def test_update_named_service_events():
    accessories = Accessories.from_file("tests/fixtures/koogeek_ls1.json")
    controller = FakeController()
    pairing = await controller.add_paired_device(accessories, "alias")

    callback = mock.Mock()
    await pairing.subscribe([(1, 8)])
    pairing.dispatcher_connect(callback)

    # Simulate that the state was changed on the device itself.
    pairing.testing.update_named_service("Light Strip", {CharacteristicsTypes.ON: True})

    assert callback.call_args_list == [mock.call({(1, 8): {"value": 1}})]


async def test_update_named_service_events_manual_accessory():
    accessories = Accessories()
    accessory = Accessory.create_with_info(
        name="TestLight",
        manufacturer="Test Mfr",
        model="Test Bulb",
        serial_number="1234",
        firmware_revision="1.1",
    )
    service = accessory.add_service(ServicesTypes.LIGHTBULB, name="Light Strip")
    on_char = service.add_char(CharacteristicsTypes.ON)
    accessories.add_accessory(accessory)

    controller = FakeController()
    pairing = await controller.add_paired_device(accessories, "alias")

    callback = mock.Mock()
    await pairing.subscribe([(accessory.aid, on_char.iid)])
    pairing.dispatcher_connect(callback)

    # Simulate that the state was changed on the device itself.
    pairing.testing.update_named_service("Light Strip", {CharacteristicsTypes.ON: True})

    assert callback.call_args_list == [
        mock.call({(accessory.aid, on_char.iid): {"value": 1}})
    ]


async def test_update_named_service_events_manual_accessory_auto_requires():
    accessories = Accessories()
    accessory = Accessory.create_with_info(
        name="TestLight",
        manufacturer="Test Mfr",
        model="Test Bulb",
        serial_number="1234",
        firmware_revision="1.1",
    )
    service = accessory.add_service(
        ServicesTypes.LIGHTBULB, name="Light Strip", add_required=True
    )
    on_char = service[CharacteristicsTypes.ON]
    accessories.add_accessory(accessory)

    controller = FakeController()
    pairing = await controller.add_paired_device(accessories, "alias")

    callback = mock.Mock()
    await pairing.subscribe([(accessory.aid, on_char.iid)])
    pairing.dispatcher_connect(callback)

    # Simulate that the state was changed on the device itself.
    pairing.testing.update_named_service("Light Strip", {CharacteristicsTypes.ON: True})

    assert callback.call_args_list == [
        mock.call({(accessory.aid, on_char.iid): {"value": 1}})
    ]


async def test_update_aid_iid_events():
    accessories = Accessories.from_file("tests/fixtures/koogeek_ls1.json")
    controller = FakeController()
    pairing = await controller.add_paired_device(accessories, "alias")

    callback = mock.Mock()
    await pairing.subscribe([(1, 8)])
    pairing.dispatcher_connect(callback)

    # Simulate that the state was changed on the device itself.
    pairing.testing.update_aid_iid([(1, 8, True)])

    assert callback.call_args_list == [mock.call({(1, 8): {"value": 1}})]


async def test_events_are_filtered():
    accessories = Accessories.from_file("tests/fixtures/koogeek_ls1.json")
    controller = FakeController()
    pairing = await controller.add_paired_device(accessories, "alias")

    callback = mock.Mock()
    await pairing.subscribe([(1, 10)])
    pairing.dispatcher_connect(callback)

    # Simulate that the state was changed on the device itself.
    pairing.testing.update_named_service("Light Strip", {CharacteristicsTypes.ON: True})

    assert callback.call_args_list == []
