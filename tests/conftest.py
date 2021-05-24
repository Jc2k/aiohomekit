import asyncio
import errno
import logging
import os
import socket
import tempfile
import threading
import time
from unittest import mock

import pytest

from aiohomekit import Controller
from aiohomekit.controller.ip import IpPairing
from aiohomekit.model import Accessory, mixin as model_mixin
from aiohomekit.model.characteristics import CharacteristicsTypes
from aiohomekit.model.services import ServicesTypes

from tests.accessoryserver import AccessoryServer


def port_ready(port):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    try:
        s.bind(("127.0.0.1", port))
    except OSError as e:
        if e.errno == errno.EADDRINUSE:
            return True
    finally:
        s.close()

    return False


def wait_for_port_available(port: int):
    for i in range(100):
        if not port_ready(port):
            break
        time.sleep(0.1)


def wait_for_server_online(port: int):
    for i in range(100):
        if port_ready(port):
            break
        time.sleep(0.1)


@pytest.fixture
async def controller_and_unpaired_accessory(request, loop):
    config_file = tempfile.NamedTemporaryFile(delete=False)
    config_file.write(
        b"""{
        "accessory_ltpk": "7986cf939de8986f428744e36ed72d86189bea46b4dcdc8d9d79a3e4fceb92b9",
        "accessory_ltsk": "3d99f3e959a1f93af4056966f858074b2a1fdec1c5fd84a51ea96f9fa004156a",
        "accessory_pairing_id": "12:34:56:00:01:0A",
        "accessory_pin": "031-45-154",
        "c#": 1,
        "category": "Lightbulb",
        "host_ip": "127.0.0.1",
        "host_port": 51842,
        "name": "unittestLight",
        "unsuccessful_tries": 0
    }"""
    )
    config_file.close()

    # Make sure get_id() numbers are stable between tests
    model_mixin.id_counter = 0

    wait_for_port_available(51842)

    httpd = AccessoryServer(config_file.name, None)
    accessory = Accessory.create_with_info(
        "Testlicht", "lusiardi.de", "Demoserver", "0001", "0.1"
    )
    lightBulbService = accessory.add_service(ServicesTypes.LIGHTBULB)
    lightBulbService.add_char(CharacteristicsTypes.ON, value=False)
    httpd.add_accessory(accessory)

    t = threading.Thread(target=httpd.serve_forever)
    t.start()

    wait_for_server_online(51842)

    controller = Controller()

    with mock.patch("aiohomekit.zeroconf._find_data_for_device_id") as find:
        find.return_value = {
            "address": "127.0.0.1",
            "port": 51842,
            "id": "12:34:56:00:01:0A",
        }
        with mock.patch.object(controller, "load_data", lambda x: None):
            with mock.patch("aiohomekit.__main__.Controller") as c:
                c.return_value = controller
                yield controller

    try:
        await asyncio.shield(controller.shutdown())
    except asyncio.CancelledError:
        pass

    os.unlink(config_file.name)

    httpd.shutdown()
    t.join()


@pytest.fixture
async def controller_and_paired_accessory(request, loop):
    config_file = tempfile.NamedTemporaryFile(delete=False)
    config_file.write(
        b"""{
        "accessory_ltpk": "7986cf939de8986f428744e36ed72d86189bea46b4dcdc8d9d79a3e4fceb92b9",
        "accessory_ltsk": "3d99f3e959a1f93af4056966f858074b2a1fdec1c5fd84a51ea96f9fa004156a",
        "accessory_pairing_id": "12:34:56:00:01:0A",
        "accessory_pin": "031-45-154",
        "c#": 1,
        "category": "Lightbulb",
        "host_ip": "127.0.0.1",
        "host_port": 51842,
        "name": "unittestLight",
        "peers": {
            "decc6fa3-de3e-41c9-adba-ef7409821bfc": {
                "admin": true,
                "key": "d708df2fbf4a8779669f0ccd43f4962d6d49e4274f88b1292f822edc3bcf8ed8"
            }
        },
        "unsuccessful_tries": 0
    }"""
    )
    config_file.close()

    # Make sure get_id() numbers are stable between tests
    model_mixin.id_counter = 0

    wait_for_port_available(51842)

    httpd = AccessoryServer(config_file.name, None)
    accessory = Accessory.create_with_info(
        "Testlicht", "lusiardi.de", "Demoserver", "0001", "0.1"
    )
    lightBulbService = accessory.add_service(ServicesTypes.LIGHTBULB)
    lightBulbService.add_char(CharacteristicsTypes.ON, value=False)
    httpd.add_accessory(accessory)

    t = threading.Thread(target=httpd.serve_forever)
    t.start()

    wait_for_server_online(51842)

    controller_file = tempfile.NamedTemporaryFile(delete=False)
    controller_file.write(
        b"""{
        "alias": {
            "Connection": "IP",
            "iOSDeviceLTPK": "d708df2fbf4a8779669f0ccd43f4962d6d49e4274f88b1292f822edc3bcf8ed8",
            "iOSPairingId": "decc6fa3-de3e-41c9-adba-ef7409821bfc",
            "AccessoryLTPK": "7986cf939de8986f428744e36ed72d86189bea46b4dcdc8d9d79a3e4fceb92b9",
            "AccessoryPairingID": "12:34:56:00:01:0A",
            "AccessoryPort": 51842,
            "AccessoryIP": "127.0.0.1",
            "iOSDeviceLTSK": "fa45f082ef87efc6c8c8d043d74084a3ea923a2253e323a7eb9917b4090c2fcc"
        }
    }"""
    )
    controller_file.close()

    controller = Controller()
    controller.load_data(controller_file.name)
    config_file.close()

    with mock.patch("aiohomekit.zeroconf._find_data_for_device_id") as find:
        find.return_value = {
            "address": "127.0.0.1",
            "port": 51842,
            "id": "12:34:56:00:01:0A",
        }
        with mock.patch.object(controller, "load_data", lambda x: None):
            with mock.patch("aiohomekit.__main__.Controller") as c:
                c.return_value = controller
                yield controller

    try:
        await asyncio.shield(controller.shutdown())
    except asyncio.CancelledError:
        pass

    os.unlink(config_file.name)
    os.unlink(controller_file.name)

    httpd.shutdown()
    t.join()


@pytest.fixture
async def pairing(controller_and_paired_accessory):
    pairing = controller_and_paired_accessory.get_pairings()["alias"]
    yield pairing
    try:
        await pairing.close()
    except asyncio.CancelledError:
        pass


@pytest.fixture
async def pairings(request, controller_and_paired_accessory, loop):
    """ Returns a pairing of pairngs. """
    left = controller_and_paired_accessory.get_pairings()["alias"]

    right = IpPairing(left.controller, left.pairing_data)

    yield (left, right)

    try:
        await asyncio.shield(right.close())
    except asyncio.CancelledError:
        pass


@pytest.fixture(autouse=True)
def configure_test_logging(caplog):
    caplog.set_level(logging.DEBUG)
