#
# Copyright 2019 aiohomekit team
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

"""Helpers for detecing homekit devices via zeroconf."""

from _socket import inet_ntoa
import asyncio
from functools import partial
import logging
import threading
from time import sleep
from typing import Any, Callable, Dict, List, Optional, Tuple, Union

from zeroconf import Error, ServiceBrowser, ServiceInfo, Zeroconf

from aiohomekit.exceptions import AccessoryNotFoundError
from aiohomekit.model import Categories
from aiohomekit.model.feature_flags import FeatureFlags
from aiohomekit.model.status_flags import IpStatusFlags

HAP_TYPE = "_hap._tcp.local."

logger = logging.getLogger(__name__)


class CollectingListener:
    """Helper class to collect all zeroconf announcements."""

    def __init__(self, max_attempts=2, device_id=None, found_device_event=None) -> None:
        """Init the listener."""
        self.data = []
        self._max_attempts = max_attempts
        self._device_id = device_id
        self._found_device_event = found_device_event

    def remove_service(self, zeroconf, zeroconf_type, name):
        """Remove a device that is no longer visible via zeroconf."""
        # this is ignored since not interested in disappearing stuff
        pass

    def add_service(self, zeroconf, zeroconf_type, name):
        """Add a device that became visible via zeroconf."""
        info = None
        attempts = 0
        while info is None and attempts < self._max_attempts:
            try:
                info = zeroconf.get_service_info(zeroconf_type, name)
            except Error:
                logger.warning(
                    "Cannot finish discovering %s as it has an invalid discovery record",
                    name,
                )
                break
            except OSError:
                break
            attempts += 1

        if not info:
            return

        self.data.append(info)

        if not self._device_id or b"id" not in info.properties:
            return

        if info.properties[b"id"].decode() == self._device_id:
            self._found_device_event.set()

    update_service = add_service

    def get_data(self) -> List[ServiceInfo]:
        """
        Use this method to get the data of the collected announcements.

        :return: a List of zeroconf.ServiceInfo instances
        """
        return self.data


def _async_homekit_devices_from_cache(
    zeroconf: Zeroconf, filter_func: Callable = None
) -> List[Dict[str, Any]]:
    """Return all homekit devices in the cache."""
    devices = []
    for name in zeroconf.cache.names():
        if not name.endswith(HAP_TYPE):
            continue
        info = ServiceInfo(HAP_TYPE, name)
        info.load_from_cache(zeroconf)
        if not _service_info_is_homekit_device(info):
            continue
        if filter_func and not filter_func(info):
            continue
        devices.append(_build_data_from_service_info(info))
    return devices


def _async_device_data_zeroconf_cache(
    device_id: str, zeroconf: Zeroconf
) -> Dict[str, Any]:
    """Find a homekit device in the zeroconf cache."""
    device_id_bytes = device_id.encode()
    devices = _async_homekit_devices_from_cache(
        zeroconf, lambda info: info.properties[b"id"] == device_id_bytes
    )
    if not devices:
        raise AccessoryNotFoundError("Device not found from active ServiceBrower")
    logging.debug("Located Homekit IP accessory %s", devices[0])
    return devices[0]


def get_from_properties(
    props: Dict[str, str],
    key: str,
    default: Optional[Union[int, str]] = None,
    case_sensitive: bool = True,
) -> Optional[str]:
    """Convert zeroconf properties to our format.

    This function looks up the key in the given zeroconf service information properties. Those are a dict between bytes.
    The key to lookup is therefore also of type bytes.
    :param props: a dict from bytes to bytes.
    :param key: bytes as key
    :param default: the value to return, if the key was not found. Will be converted to str.
    :param case_sensitive: If this is False, try to lookup keys also when they only match ignoring their case
    :return: the value out of the dict as string (after decoding), the given default if the key was not not found but
             the default was given or None
    """
    if case_sensitive:
        tmp_props = props
        tmp_key = key
    else:
        tmp_props = {k.lower(): props[k] for k in props}
        tmp_key = key.lower()

    if tmp_key in tmp_props:
        return tmp_props[tmp_key]

    if default:
        return str(default)

    return None


def _service_info_is_homekit_device(service_info: ServiceInfo) -> bool:
    props = service_info.properties
    return (
        service_info.addresses and b"c#" in props and b"md" in props and b"id" in props
    )


def discover_homekit_devices(
    max_seconds: int = 10, zeroconf_instance: Zeroconf = None
) -> List[Any]:
    """Discovers all HomeKit Accessories.

    It browses for devices in the _hap._tcp.local. domain and checks if
    all required fields are set in the text record. It one field is missing, it will be excluded from the result list.

    :param max_seconds: the number of seconds we will wait for the devices to be discovered
    :return: a list of dicts containing all fields as described in table 5.7 page 69
    """
    our_zc = zeroconf_instance or Zeroconf()
    listener = CollectingListener()
    service_browser = ServiceBrowser(our_zc, HAP_TYPE, listener)
    sleep(max_seconds)
    tmp = []
    try:
        for info in listener.get_data():
            if not _service_info_is_homekit_device(info):
                continue
            data = _build_data_from_service_info(info)
            logging.debug("found Homekit IP accessory %s", data)
            tmp.append(data)
    finally:
        service_browser.cancel()
        if not zeroconf_instance:
            our_zc.close()
    return tmp


def _build_data_from_service_info(service_info) -> Dict[str, Any]:
    """Construct data from service_info."""
    # from Bonjour discovery
    data = {
        "name": service_info.name,
        "address": inet_ntoa(service_info.addresses[0]),
        "port": service_info.port,
    }

    logging.debug("candidate data %s", service_info.properties)

    data.update(
        parse_discovery_properties(decode_discovery_properties(service_info.properties))
    )

    return data


def decode_discovery_properties(props: Dict[bytes, bytes]) -> Dict[str, str]:
    """Decode unicode bytes in _hap._tcp Bonjour TXT record keys to python strings.

    :params: a dictionary of key/value TXT records from Bonjour discovery. These are assumed
    to be bytes type.
    :return: A dictionary of key/value TXT records from Bonjour discovery. These are now str.
    """
    return {k.decode("utf-8"): value.decode("utf-8") for k, value in props.items()}


def parse_discovery_properties(props: Dict[str, str]) -> Dict[str, Union[str, int]]:
    """Normalize and parse _hap._tcp Bonjour TXT record keys.

    This is done automatically if you are using the discovery features built in to the library. If you are
    integrating into an existing system it may already do its own Bonjour discovery. In that case you can
    call this function to normalize the properties it has discovered.

    :param props: a dictionary of key/value TXT records from doing Bonjour discovery. These should be
    decoded as strings already. Byte data should be decoded with decode_discovery_properties.
    :return: A dictionary contained the parsed and normalized data.
    """
    data = {}

    # stuff taken from the Bonjour TXT record (see table 5-7 on page 69)
    for prop in ("c#", "id", "md", "s#", "ci", "sf"):
        prop_val = get_from_properties(props, prop, case_sensitive=False)
        if prop_val:
            data[prop] = prop_val

    feature_flags = get_from_properties(props, "ff", case_sensitive=False)
    if feature_flags:
        flags = int(feature_flags)
    else:
        flags = 0
    data["ff"] = flags
    data["flags"] = FeatureFlags(flags)

    protocol_version = get_from_properties(
        props, "pv", case_sensitive=False, default="1.0"
    )
    if protocol_version:
        data["pv"] = protocol_version

    if "sf" in data:
        data["statusflags"] = IpStatusFlags[int(data["sf"])]

    if "ci" in data:
        data["category"] = Categories[int(data["ci"])]

    return data


def _find_data_for_device_id(
    device_id: str, max_seconds: int = 10, zeroconf_instance: Zeroconf = None
) -> Tuple[str, int]:
    """Try to find a HomeKit Accessory via Bonjour.

    The process is time boxed by the second parameter which sets an upper
    limit of `max_seconds` before it times out. The runtime of the function may be longer because of the Bonjour
    handling code.
    """
    our_zc = zeroconf_instance or Zeroconf()
    found_device_event = threading.Event()
    listener = CollectingListener(
        device_id=device_id, found_device_event=found_device_event
    )
    service_browser = ServiceBrowser(our_zc, HAP_TYPE, listener)
    found_device_event.wait(timeout=max_seconds)
    device_id_bytes = device_id.encode()

    try:
        for info in listener.get_data():
            if not _service_info_is_homekit_device(info):
                continue
            if info.properties[b"id"] == device_id_bytes:
                logging.debug("Located Homekit IP accessory %s", info.properties)
                return _build_data_from_service_info(info)
    finally:
        service_browser.cancel()
        if not zeroconf_instance:
            our_zc.close()

    raise AccessoryNotFoundError("Device not found via Bonjour within 10 seconds")


def async_zeroconf_has_hap_service_browser(zeroconf_instance: Zeroconf) -> bool:
    """Check to see if the zeroconf instance has an active HAP ServiceBrowser."""
    return any(
        isinstance(listener, ServiceBrowser) and HAP_TYPE in listener.types
        for listener in zeroconf_instance.listeners
    )


async def async_find_device_ip_and_port(
    device_id: str, max_seconds: int = 10, zeroconf_instance: Zeroconf = None
) -> Tuple[str, int]:
    """Find the ip and port for a device id."""
    data = await async_find_data_for_device_id(
        device_id, max_seconds, zeroconf_instance
    )
    return (data["address"], data["port"])


async def async_find_data_for_device_id(
    device_id: str, max_seconds: int = 10, zeroconf_instance: Zeroconf = None
) -> Dict[str, Any]:
    """Find normalized data (properties) for a device id."""
    if zeroconf_instance and async_zeroconf_has_hap_service_browser(zeroconf_instance):
        return _async_device_data_zeroconf_cache(device_id, zeroconf_instance)

    return await asyncio.get_event_loop().run_in_executor(
        None,
        partial(
            _find_data_for_device_id,
            device_id=device_id,
            max_seconds=max_seconds,
            zeroconf_instance=zeroconf_instance,
        ),
    )


async def async_discover_homekit_devices(
    max_seconds=10, zeroconf_instance: Zeroconf = None
):
    """Discover all homekit devices available to zeroconf/bonjour."""
    if zeroconf_instance and async_zeroconf_has_hap_service_browser(zeroconf_instance):
        return _async_homekit_devices_from_cache(zeroconf_instance)

    return await asyncio.get_event_loop().run_in_executor(
        None,
        partial(
            discover_homekit_devices,
            max_seconds=max_seconds,
            zeroconf_instance=zeroconf_instance,
        ),
    )
