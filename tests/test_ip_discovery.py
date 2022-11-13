from aiohomekit import Controller
from aiohomekit.controller.ip import IpDiscovery, IpPairing
from aiohomekit.model.categories import Categories
from aiohomekit.zeroconf import HomeKitService


async def test_pair(controller_and_unpaired_accessory: tuple[Controller, int]):
    controller, port = controller_and_unpaired_accessory

    discovery = IpDiscovery(
        controller,
        HomeKitService(
            name="Test",
            id="00:01:02:03:04:05",
            model="Test",
            feature_flags=0,
            status_flags=1,
            config_num=0,
            state_num=0,
            category=Categories.OTHER,
            protocol_version="1.0",
            type="_hap._tcp.local",
            address="127.0.0.1",
            addresses=["127.0.0.1"],
            port=port,
        ),
    )

    finish_pairing = await discovery.async_start_pairing("alias")
    pairing = await finish_pairing("031-45-154")

    assert isinstance(pairing, IpPairing)

    assert await pairing.get_characteristics([(1, 9)]) == {
        (1, 9): {"value": False},
    }


async def test_identify(controller_and_unpaired_accessory: tuple[Controller, int]):
    controller, port = controller_and_unpaired_accessory

    discovery = IpDiscovery(
        controller,
        HomeKitService(
            name="Test",
            id="00:01:02:03:04:05",
            model="Test",
            feature_flags=0,
            status_flags=0,
            config_num=0,
            state_num=0,
            category=Categories.OTHER,
            protocol_version="1.0",
            type="_hap._tcp.local",
            address="127.0.0.1",
            addresses=["127.0.0.1"],
            port=port,
        ),
    )

    identified = await discovery.async_identify()
    assert identified is True
