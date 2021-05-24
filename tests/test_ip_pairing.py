import asyncio
from unittest import mock
import pytest

from aiohomekit.protocol.statuscodes import HapStatusCodes


async def test_list_accessories(pairing):
    accessories = await pairing.list_accessories_and_characteristics()
    assert accessories[0]["aid"] == 1
    assert accessories[0]["services"][0]["iid"] == 1

    char = accessories[0]["services"][0]["characteristics"][0]
    print(char)
    assert char["description"] == "Identify"
    assert char["iid"] == 2
    assert char["format"] == "bool"
    assert char["perms"] == ["pw"]
    assert char["type"] == "00000014-0000-1000-8000-0026BB765291"


async def test_get_characteristics(pairing):
    characteristics = await pairing.get_characteristics([(1, 9)])

    assert characteristics[(1, 9)] == {"value": False}


async def test_get_characteristics_after_failure(pairing):
    characteristics = await pairing.get_characteristics([(1, 9)])

    assert characteristics[(1, 9)] == {"value": False}

    pairing.connection.transport.close()
    await asyncio.sleep(0)
    assert not pairing.connection.is_connected

    characteristics = await pairing.get_characteristics([(1, 9)])

    assert characteristics[(1, 9)] == {"value": False}


async def test_reconnect_soon_after_disconnected(pairing):
    characteristics = await pairing.get_characteristics([(1, 9)])

    assert characteristics[(1, 9)] == {"value": False}

    assert pairing.connection.is_connected

    pairing.connection.transport.close()
    await asyncio.sleep(0)
    assert not pairing.connection.is_connected

    # Ensure we can safely call multiple times
    await pairing.connection.reconnect_soon()
    await pairing.connection.reconnect_soon()
    await pairing.connection.reconnect_soon()

    await asyncio.wait_for(pairing.connection._connector, timeout=0.5)
    assert pairing.connection.is_connected

    characteristics = await pairing.get_characteristics([(1, 9)])

    assert characteristics[(1, 9)] == {"value": False}


async def test_reconnect_soon_after_device_is_offline_for_a_bit(pairing):
    characteristics = await pairing.get_characteristics([(1, 9)])

    assert characteristics[(1, 9)] == {"value": False}

    assert pairing.connection.is_connected

    with mock.patch(
        "aiohomekit.controller.ip.connection.HomeKitConnection._connect_once",
        side_effect=asyncio.TimeoutError,
    ):
        pairing.connection.transport.close()
        await asyncio.sleep(0)
        assert not pairing.connection.is_connected

        for _ in range(3):
            await pairing.connection.reconnect_soon()
            with pytest.raises(asyncio.TimeoutError):
                await asyncio.wait_for(
                    asyncio.shield(pairing.connection._connector), timeout=0.2
                )
            assert not pairing.connection.is_connected

    await pairing.connection.reconnect_soon()
    await asyncio.wait_for(pairing.connection._connector, timeout=0.5)
    assert pairing.connection.is_connected

    characteristics = await pairing.get_characteristics([(1, 9)])

    assert characteristics[(1, 9)] == {"value": False}


async def test_put_characteristics(pairing):
    characteristics = await pairing.put_characteristics([(1, 9, True)])

    assert characteristics == {}

    characteristics = await pairing.get_characteristics([(1, 9)])

    assert characteristics[(1, 9)] == {"value": True}


async def test_subscribe(pairing):
    assert pairing.subscriptions == set()

    await pairing.subscribe([(1, 9)])

    assert pairing.subscriptions == {(1, 9)}

    characteristics = await pairing.get_characteristics([(1, 9)], include_events=True)

    assert characteristics == {(1, 9): {"ev": True, "value": False}}


async def test_unsubscribe(pairing):
    await pairing.subscribe([(1, 9)])

    assert pairing.subscriptions == {(1, 9)}

    characteristics = await pairing.get_characteristics([(1, 9)], include_events=True)

    assert characteristics == {(1, 9): {"ev": True, "value": False}}

    await pairing.unsubscribe([(1, 9)])

    assert pairing.subscriptions == set()

    characteristics = await pairing.get_characteristics([(1, 9)], include_events=True)

    assert characteristics == {(1, 9): {"ev": False, "value": False}}


async def test_dispatcher_connect(pairing):
    assert pairing.listeners == set()

    def callback(x):
        pass

    cancel = pairing.dispatcher_connect(callback)
    assert pairing.listeners == {callback}

    cancel()
    assert pairing.listeners == set()


async def test_receiving_events(pairings):
    """
    Test that can receive events when change happens in another session.

    We set up 2 controllers both with active secure sessions. One
    subscribes and then other does put() calls.

    This test is currently skipped because accessory server doesnt
    support events.
    """
    left, right = pairings

    event_value = None
    ev = asyncio.Event()

    def handler(data):
        print(data)
        nonlocal event_value
        event_value = data
        ev.set()

    # Set where to send events
    right.dispatcher_connect(handler)

    # Set what events to get
    await right.subscribe([(1, 9)])

    # Trigger an event by writing a change on the other connection
    await left.put_characteristics([(1, 9, True)])

    # Wait for event to be received for up to 5s
    await asyncio.wait_for(ev.wait(), 5)

    assert event_value == {(1, 9): {"value": True}}


async def test_subscribe_invalid_iid(pairing):
    """
    Test that can get an error when subscribing to an invalid iid.
    """
    result = await pairing.subscribe([(1, 999999)])
    assert result == {
        (1, 999999): {
            "description": "Resource does not exist.",
            "status": HapStatusCodes.RESOURCE_NOT_EXIST,
        }
    }


async def test_list_pairings(pairing):
    pairings = await pairing.list_pairings()
    assert pairings == [
        {
            "controllerType": "admin",
            "pairingId": "decc6fa3-de3e-41c9-adba-ef7409821bfc",
            "permissions": 1,
            "publicKey": "d708df2fbf4a8779669f0ccd43f4962d6d49e4274f88b1292f822edc3bcf8ed8",
        }
    ]


async def test_add_pairings(pairing):
    await pairing.add_pairing(
        "decc6fa3-de3e-41c9-adba-ef7409821bfe",
        "d708df2fbf4a8779669f0ccd43f4962d6d49e4274f88b1292f822edc3bcf8ed7",
        "User",
    )

    pairings = await pairing.list_pairings()
    assert pairings == [
        {
            "controllerType": "admin",
            "pairingId": "decc6fa3-de3e-41c9-adba-ef7409821bfc",
            "permissions": 1,
            "publicKey": "d708df2fbf4a8779669f0ccd43f4962d6d49e4274f88b1292f822edc3bcf8ed8",
        },
        {
            "controllerType": "regular",
            "pairingId": "decc6fa3-de3e-41c9-adba-ef7409821bfe",
            "permissions": 0,
            "publicKey": "d708df2fbf4a8779669f0ccd43f4962d6d49e4274f88b1292f822edc3bcf8ed7",
        },
    ]


async def test_add_and_remove_pairings(pairing):
    await pairing.add_pairing(
        "decc6fa3-de3e-41c9-adba-ef7409821bfe",
        "d708df2fbf4a8779669f0ccd43f4962d6d49e4274f88b1292f822edc3bcf8ed7",
        "User",
    )

    pairings = await pairing.list_pairings()
    assert pairings == [
        {
            "controllerType": "admin",
            "pairingId": "decc6fa3-de3e-41c9-adba-ef7409821bfc",
            "permissions": 1,
            "publicKey": "d708df2fbf4a8779669f0ccd43f4962d6d49e4274f88b1292f822edc3bcf8ed8",
        },
        {
            "controllerType": "regular",
            "pairingId": "decc6fa3-de3e-41c9-adba-ef7409821bfe",
            "permissions": 0,
            "publicKey": "d708df2fbf4a8779669f0ccd43f4962d6d49e4274f88b1292f822edc3bcf8ed7",
        },
    ]

    await pairing.remove_pairing("decc6fa3-de3e-41c9-adba-ef7409821bfe")

    pairings = await pairing.list_pairings()
    assert pairings == [
        {
            "controllerType": "admin",
            "pairingId": "decc6fa3-de3e-41c9-adba-ef7409821bfc",
            "permissions": 1,
            "publicKey": "d708df2fbf4a8779669f0ccd43f4962d6d49e4274f88b1292f822edc3bcf8ed8",
        }
    ]


async def test_identify(pairing):
    identified = await pairing.identify()
    assert identified is True
