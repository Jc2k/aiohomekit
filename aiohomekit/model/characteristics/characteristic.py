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

import base64
import binascii
from decimal import Decimal
from distutils.util import strtobool
import struct
from typing import TYPE_CHECKING, Any, Dict, Optional

from aiohomekit.exceptions import CharacteristicPermissionError, FormatError
from aiohomekit.model.mixin import ToDictMixin
from aiohomekit.protocol.statuscodes import HapStatusCodes

from .characteristic_formats import CharacteristicFormats
from .characteristic_types import CharacteristicsTypes
from .data import characteristics
from .permissions import CharacteristicPermissions

if TYPE_CHECKING:
    from aiohomekit.model.service import Service


DEFAULT_FOR_TYPE = {
    CharacteristicFormats.bool: False,
    CharacteristicFormats.uint8: 0,
    CharacteristicFormats.uint16: 0,
    CharacteristicFormats.uint32: 0,
    CharacteristicFormats.uint64: 0,
    CharacteristicFormats.int: 0,
    CharacteristicFormats.float: 0.0,
    CharacteristicFormats.string: "",
    CharacteristicFormats.array: [],
    CharacteristicFormats.dict: {},
}


class Characteristic(ToDictMixin):
    def __init__(self, service: "Service", characteristic_type: str, **kwargs) -> None:
        self.service = service
        self.iid = service.accessory.get_next_id()
        try:
            self.type = CharacteristicsTypes.get_uuid(characteristic_type)
        except KeyError:
            self.type = characteristic_type

        self.perms = self._get_configuration(
            kwargs, "perms", [CharacteristicPermissions.paired_read]
        )
        self.format = self._get_configuration(kwargs, "format", None)

        self.ev = None
        self.description = self._get_configuration(kwargs, "description", None)
        self.unit = self._get_configuration(kwargs, "unit", None)
        self.minValue = self._get_configuration(kwargs, "min_value", None)
        self.maxValue = self._get_configuration(kwargs, "max_value", None)
        self.minStep = self._get_configuration(kwargs, "min_step", None)
        self.maxLen = 64
        self.maxDataLen = 2097152
        self.valid_values = self._get_configuration(kwargs, "valid_values", None)
        self.valid_values_range = None

        self.value = None

        if CharacteristicPermissions.paired_read not in self.perms:
            return

        if "value" in kwargs:
            self.value = kwargs["value"]
            return

        if self.valid_values:
            self.value = self.valid_values[0]
            return

        self.value = DEFAULT_FOR_TYPE.get(self.format, None)

        if self.minValue:
            if not self.value:
                self.value = self.minValue
            self.value = max(self.value, self.minValue)

        if self.maxValue:
            if not self.value:
                self.value = self.maxValue
            self.value = min(self.value, self.maxValue)

    def _get_configuration(
        self, kwargs: Dict[str, Any], key: str, default: Optional[Any] = None,
    ) -> Optional[Any]:
        if key in kwargs:
            return kwargs[key]
        if self.type not in characteristics:
            return default
        if key not in characteristics[self.type]:
            return default
        return characteristics[self.type][key]

    def set_events(self, new_val):
        self.ev = new_val

    def set_value(self, new_val):
        """
        This function sets the value of this characteristic. Permissions are checked first

        :param new_val:
        :raises CharacteristicPermissionError: if the characteristic cannot be written
        """
        if CharacteristicPermissions.paired_write not in self.perms:
            raise CharacteristicPermissionError(HapStatusCodes.CANT_WRITE_READ_ONLY)
        try:
            # convert input to python int if it is any kind of int
            if self.format in [
                CharacteristicFormats.uint64,
                CharacteristicFormats.uint32,
                CharacteristicFormats.uint16,
                CharacteristicFormats.uint8,
                CharacteristicFormats.int,
            ]:
                new_val = int(new_val)
            # convert input to python float
            if self.format == CharacteristicFormats.float:
                new_val = float(new_val)
            # convert to python bool
            if self.format == CharacteristicFormats.bool:
                new_val = strtobool(str(new_val))
        except ValueError:
            raise FormatError(HapStatusCodes.INVALID_VALUE)

        if self.format in [
            CharacteristicFormats.uint64,
            CharacteristicFormats.uint32,
            CharacteristicFormats.uint16,
            CharacteristicFormats.uint8,
            CharacteristicFormats.int,
            CharacteristicFormats.float,
        ]:
            if self.minValue is not None and new_val < self.minValue:
                raise FormatError(HapStatusCodes.INVALID_VALUE)
            if self.maxValue is not None and self.maxValue < new_val:
                raise FormatError(HapStatusCodes.INVALID_VALUE)
            if self.minStep is not None:
                tmp = new_val

                # if minValue is set, the steps count from this on
                if self.minValue is not None:
                    tmp -= self.minValue

                # use Decimal to calculate the module because it has not the precision problem as float...
                if Decimal(str(tmp)) % Decimal(str(self.minStep)) != 0:
                    raise FormatError(HapStatusCodes.INVALID_VALUE)
            if self.valid_values is not None and new_val not in self.valid_values:
                raise FormatError(HapStatusCodes.INVALID_VALUE)
            if self.valid_values_range is not None and not (
                self.valid_values_range[0] <= new_val <= self.valid_values_range[1]
            ):
                raise FormatError(HapStatusCodes.INVALID_VALUE)

        if self.format == CharacteristicFormats.data:
            try:
                byte_data = base64.decodebytes(new_val.encode())
            except binascii.Error:
                raise FormatError(HapStatusCodes.INVALID_VALUE)
            except Exception:
                raise FormatError(HapStatusCodes.OUT_OF_RESOURCES)
            if self.maxDataLen < len(byte_data):
                raise FormatError(HapStatusCodes.INVALID_VALUE)

        if self.format == CharacteristicFormats.string:
            if len(new_val) > self.maxLen:
                raise FormatError(HapStatusCodes.INVALID_VALUE)

        self.value = new_val

    def set_value_from_ble(self, value):
        if self.format == CharacteristicFormats.bool:
            value = struct.unpack("?", value)[0]
        elif self.format == CharacteristicFormats.uint8:
            value = struct.unpack("B", value)[0]
        elif self.format == CharacteristicFormats.uint16:
            value = struct.unpack("H", value)[0]
        elif self.format == CharacteristicFormats.uint32:
            value = struct.unpack("I", value)[0]
        elif self.format == CharacteristicFormats.uint64:
            value = struct.unpack("Q", value)[0]
        elif self.format == CharacteristicFormats.int:
            value = struct.unpack("i", value)[0]
        elif self.format == CharacteristicFormats.float:
            value = struct.unpack("f", value)[0]
        elif self.format == CharacteristicFormats.string:
            value = value.decode("UTF-8")
        else:
            value = value.hex()

        self.set_value(value)

    def get_value(self):
        """
        This method returns the value of this characteristic. Permissions are checked first, then either the callback
        for getting the values is executed (execution time may vary) or the value is directly returned if not callback
        is given.

        :raises CharacteristicPermissionError: if the characteristic cannot be read
        :return: the value of the characteristic
        """
        if CharacteristicPermissions.paired_read not in self.perms:
            raise CharacteristicPermissionError(HapStatusCodes.CANT_READ_WRITE_ONLY)
        return self.value

    def get_value_for_ble(self):
        value = self.get_value()

        if self.format == CharacteristicFormats.bool:
            try:
                val = strtobool(str(value))
            except ValueError:
                raise FormatError(
                    '"{v}" is no valid "{t}"!'.format(v=value, t=self.format)
                )

            value = struct.pack("?", val)
        elif self.format == CharacteristicFormats.int:
            value = struct.pack("i", int(value))
        elif self.format == CharacteristicFormats.float:
            value = struct.pack("f", float(value))
        elif self.format == CharacteristicFormats.string:
            value = value.encode()

        return value

    def get_meta(self):
        """
        This method returns a dict of meta information for this characteristic. This includes at least the format of
        the characteristic but may contain any other specific attribute.

        :return: a dict
        """
        tmp = {"format": self.format}
        # TODO implement handling of already defined maxLen (upto 256!)
        if self.format == CharacteristicFormats.string:
            tmp["maxLen"] = 64
        # TODO implement handling of other fields! eg maxDataLen
        return tmp

    def to_accessory_and_service_list(self):
        d = {
            "type": self.type,
            "iid": self.iid,
            "perms": self.perms,
            "format": self.format,
        }
        if CharacteristicPermissions.paired_read in self.perms:
            d["value"] = self.value
        if self.ev:
            d["ev"] = self.ev
        if self.description:
            d["description"] = self.description
        if self.unit:
            d["unit"] = self.unit
        if self.minValue:
            d["minValue"] = self.minValue
        if self.maxValue:
            d["maxValue"] = self.maxValue
        if self.minStep:
            d["minStep"] = self.minStep
        if self.maxLen and self.format in [CharacteristicFormats.string]:
            d["maxLen"] = self.maxLen
        if self.valid_values:
            d["valid-values"] = self.valid_values
        return d
