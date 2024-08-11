import asyncio
from datetime import timedelta
from typing import Any
from unittest import mock

import pytest

from aiohomekit.controller.ip.pairing import IpPairing
from aiohomekit.exceptions import AccessoryDisconnectedError
from aiohomekit.model import Transport
from aiohomekit.protocol.statuscodes import HapStatusCode


async def test_list_accessories(pairing: IpPairing):
    accessories = await pairing.list_accessories_and_characteristics()
    assert accessories[0]["aid"] == 1
    assert accessories[0]["services"][0]["iid"] == 1

    char = accessories[0]["services"][0]["characteristics"][0]

    assert char["description"] == "Identify"
    assert char["iid"] == 2
    assert char["format"] == "bool"
    assert char["perms"] == ["pw"]
    assert char["type"] == "00000014-0000-1000-8000-0026BB765291"


async def test_get_characteristics(pairing: IpPairing):
    characteristics = await pairing.get_characteristics([(1, 9)])

    assert characteristics[(1, 9)] == {"value": False}


async def test_duplicate_get_characteristics(pairing):
    characteristics = await pairing.get_characteristics([(1, 9), (1, 9)])
    assert characteristics[(1, 9)] == {"value": False}


async def test_get_characteristics_after_failure(pairing: IpPairing):
    characteristics = await pairing.get_characteristics([(1, 9)])

    assert characteristics[(1, 9)] == {"value": False}

    pairing.connection.transport.close()
    await asyncio.sleep(0)
    assert not pairing.connection.is_connected
    assert not pairing.is_available

    characteristics = await pairing.get_characteristics([(1, 9)])

    assert characteristics[(1, 9)] == {"value": False}


async def test_reconnect_soon_after_disconnected(pairing: IpPairing):
    characteristics = await pairing.get_characteristics([(1, 9)])

    assert characteristics[(1, 9)] == {"value": False}

    assert pairing.connection.is_connected
    assert pairing.is_available

    pairing.connection.transport.close()
    await asyncio.sleep(0)
    assert not pairing.connection.is_connected
    assert not pairing.is_available

    # Ensure we can safely call multiple times
    pairing._async_description_update(None)
    pairing._async_description_update(None)
    pairing._async_description_update(None)

    await asyncio.sleep(
        0
    )  # ensure the callback has a chance to run and create _connector
    await asyncio.wait_for(pairing.connection._connector, timeout=0.5)
    assert pairing.connection.is_connected

    characteristics = await pairing.get_characteristics([(1, 9)])

    assert characteristics[(1, 9)] == {"value": False}


async def test_reconnect_soon_after_device_is_offline_for_a_bit(pairing: IpPairing):
    characteristics = await pairing.get_characteristics([(1, 9)])

    assert characteristics[(1, 9)] == {"value": False}

    assert pairing.connection.is_connected
    assert pairing.is_available

    with mock.patch(
        "aiohomekit.controller.ip.connection.HomeKitConnection._connect_once",
        side_effect=asyncio.TimeoutError,
    ):
        pairing.connection.transport.close()
        await asyncio.sleep(0)
        assert not pairing.connection.is_connected
        assert not pairing.is_available

        for _ in range(3):
            pairing._async_description_update(None)
            # ensure the callback has a chance to run and create _connector
            await asyncio.sleep(0)
            with pytest.raises(asyncio.TimeoutError):
                await asyncio.wait_for(
                    asyncio.shield(pairing.connection._connector), timeout=0.2
                )
            assert not pairing.connection.is_connected

    pairing._async_description_update(None)
    await asyncio.wait_for(pairing.connection._connector, timeout=0.5)
    assert pairing.connection.is_connected
    assert pairing.is_available

    characteristics = await pairing.get_characteristics([(1, 9)])

    assert characteristics[(1, 9)] == {"value": False}


async def test_reconnect_soon_on_device_reboot(pairing: IpPairing):
    characteristics = await pairing.get_characteristics([(1, 9)])

    assert characteristics[(1, 9)] == {"value": False}

    assert pairing.connection.is_connected
    assert pairing.is_available

    with mock.patch(
        "aiohomekit.controller.ip.connection.HomeKitConnection._connect_once",
        side_effect=asyncio.TimeoutError,
    ):
        pairing.connection.protocol.connection_lost(OSError("Connection reset by peer"))
        await asyncio.sleep(0)
        assert not pairing.connection.is_connected
        assert not pairing.is_available

        for _ in range(3):
            pairing._async_description_update(None)
            # ensure the callback has a chance to run and create _connector
            await asyncio.sleep(0)
            with pytest.raises(asyncio.TimeoutError):
                await asyncio.wait_for(
                    asyncio.shield(pairing.connection._connector), timeout=0.2
                )
            assert not pairing.connection.is_connected

    pairing._async_description_update(None)
    await asyncio.wait_for(pairing.connection._connector, timeout=0.5)
    assert pairing.connection.is_connected
    assert pairing.is_available

    characteristics = await pairing.get_characteristics([(1, 9)])

    assert characteristics[(1, 9)] == {"value": False}


async def test_put_characteristics(pairing: IpPairing):
    characteristics = await pairing.put_characteristics([(1, 9, True)])

    assert characteristics == {}

    characteristics = await pairing.get_characteristics([(1, 9)])

    assert characteristics[(1, 9)] == {"value": True}


async def test_put_characteristics_cancelled(pairing: IpPairing):
    characteristics = await pairing.put_characteristics([(1, 9, True)])
    characteristics = await pairing.get_characteristics([(1, 9)])

    with mock.patch.object(pairing.connection.transport, "write"):
        task = asyncio.create_task(pairing.put_characteristics([(1, 9, False)]))
        await asyncio.sleep(0)
        for future in pairing.connection.protocol.result_cbs:
            future.cancel()
        await asyncio.sleep(0)
        with pytest.raises(asyncio.CancelledError):
            await task

    # We should wait a few seconds to see if the
    # connection can be re-established and the write can be
    # completed. But this is not currently possible because
    # we do not wait for the connection to be re-established
    # before we try to write the data. When we implement
    # reconnection we should remove this pytest.raises
    # and the sleep below.
    with pytest.raises(AccessoryDisconnectedError):
        await pairing.get_characteristics([(1, 9)])

    await asyncio.sleep(0)
    characteristics = await pairing.get_characteristics([(1, 9)])
    assert characteristics[(1, 9)] == {"value": True}


async def test_put_characteristics_callbacks(pairing: IpPairing):
    events = []

    def process_new_events(
        new_values_dict: dict[tuple[int, int], dict[str, Any]]
    ) -> None:
        events.append(new_values_dict)

    pairing.dispatcher_connect(process_new_events)
    assert events == []

    characteristics = await pairing.put_characteristics([(1, 9, True)])
    assert events == [{}, {(1, 9): {"value": True}}]
    assert characteristics == {}

    # Identify is a write only characteristic, so we should not get a callback
    characteristics = await pairing.put_characteristics([(1, 2, True)])
    assert events == [{}, {(1, 9): {"value": True}}]

    characteristics = await pairing.get_characteristics([(1, 9)])

    assert characteristics[(1, 9)] == {"value": True}

    characteristics = await pairing.get_characteristics({(1, 9)})

    assert characteristics[(1, 9)] == {"value": True}


async def test_subscribe(pairing: IpPairing):
    assert pairing.subscriptions == set()

    await pairing.subscribe([(1, 9)])

    assert pairing.subscriptions == {(1, 9)}

    characteristics = await pairing.get_characteristics([(1, 9)])

    assert characteristics == {(1, 9): {"value": False}}


async def test_unsubscribe(pairing: IpPairing):
    await pairing.subscribe([(1, 9)])

    assert pairing.subscriptions == {(1, 9)}

    characteristics = await pairing.get_characteristics([(1, 9)])

    assert characteristics == {(1, 9): {"value": False}}

    await pairing.unsubscribe([(1, 9)])

    assert pairing.subscriptions == set()

    characteristics = await pairing.get_characteristics([(1, 9)])

    assert characteristics == {(1, 9): {"value": False}}


async def test_dispatcher_connect(pairing: IpPairing):
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
    left: IpPairing = pairings[0]
    right: IpPairing = pairings[1]

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


async def test_subscribe_invalid_iid(pairing: IpPairing):
    """
    Test that can get an error when subscribing to an invalid iid.
    """
    result = await pairing.subscribe([(1, 999999)])
    assert result == {
        (1, 999999): {
            "description": "Resource does not exist.",
            "status": HapStatusCode.RESOURCE_NOT_EXIST.value,
        }
    }


async def test_list_pairings(pairing: IpPairing):
    pairings = await pairing.list_pairings()
    assert pairings == [
        {
            "controllerType": "admin",
            "pairingId": "decc6fa3-de3e-41c9-adba-ef7409821bfc",
            "permissions": 1,
            "publicKey": "d708df2fbf4a8779669f0ccd43f4962d6d49e4274f88b1292f822edc3bcf8ed8",
        }
    ]


async def test_add_pairings(pairing: IpPairing):
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


async def test_add_and_remove_pairings(pairing: IpPairing):
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


async def test_transport_property(pairing: IpPairing):
    assert pairing.transport == Transport.IP


async def test_polling_property(pairing: IpPairing):
    assert pairing.poll_interval == timedelta(seconds=60)


async def test_put_characteristics_invalid_value(pairing: IpPairing):
    aid, iid = (1, 2)
    characteristics = [(aid, iid, 100)]
    status_code = await pairing.put_characteristics(characteristics)
    assert status_code is not None
    assert status_code[(aid, iid)] is not None
    assert status_code[(aid, iid)]["status"] == HapStatusCode.INVALID_VALUE.value
