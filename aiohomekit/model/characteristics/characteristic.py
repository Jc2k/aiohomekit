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
from decimal import ROUND_HALF_UP, Decimal, localcontext
from distutils.util import strtobool
from typing import TYPE_CHECKING, Any, Dict, Optional

from aiohomekit.exceptions import CharacteristicPermissionError, FormatError
from aiohomekit.protocol.statuscodes import HapStatusCode
from aiohomekit.protocol.tlv import TLV, TlvParseException
from aiohomekit.tlv8 import tlv_array

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

INTEGER_TYPES = [
    CharacteristicFormats.uint64,
    CharacteristicFormats.uint32,
    CharacteristicFormats.uint16,
    CharacteristicFormats.uint8,
    CharacteristicFormats.int,
]

NUMBER_TYPES = INTEGER_TYPES + [CharacteristicFormats.float]


class Characteristic:
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

        self._value = None
        self._status = HapStatusCode(0)

        if CharacteristicPermissions.paired_read not in self.perms:
            return

        if "value" in kwargs:
            self._value = kwargs["value"]
            return

        if self.valid_values:
            self._value = self.valid_values[0]
            return

        self._value = DEFAULT_FOR_TYPE.get(self.format, None)

        if self.minValue:
            if not self._value:
                self._value = self.minValue
            self._value = max(self._value, self.minValue)

        if self.maxValue:
            if not self._value:
                self._value = self.maxValue
            self._value = min(self._value, self.maxValue)

    def _get_configuration(
        self,
        kwargs: Dict[str, Any],
        key: str,
        default: Optional[Any] = None,
    ) -> Optional[Any]:
        if key in kwargs:
            return kwargs[key]
        if self.type not in characteristics:
            return default
        if key not in characteristics[self.type]:
            return default
        return characteristics[self.type][key]

    @property
    def type_name(self):
        try:
            return CharacteristicsTypes.get_short(self.type)
        except KeyError:
            return None

    @property
    def status(self) -> HapStatusCode:
        return self._status

    @status.setter
    def status(self, status: HapStatusCode):
        self._status = status

    @property
    def available(self) -> bool:
        return self._status != HapStatusCode.UNABLE_TO_COMMUNICATE

    def set_events(self, new_val):
        self.ev = new_val

    def set_value(self, new_val):
        """
        This function sets the value of this characteristic.
        """
        self._value = new_val

    @property
    def value(self):
        if self.format == CharacteristicFormats.tlv8:
            extra_data = characteristics.get(self.type, {})

            new_val = base64.b64decode(self._value)
            struct = extra_data.get("struct")
            if struct:
                if extra_data.get("array"):
                    return [struct.decode(new_val) for new_val in tlv_array(new_val)]
                else:
                    return struct.decode(new_val)

        return self._value

    @value.setter
    def value(self, value):
        self.set_value(value)

    def validate_value(self, new_val):
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
            raise FormatError(HapStatusCode.INVALID_VALUE)

        if self.format in [
            CharacteristicFormats.uint64,
            CharacteristicFormats.uint32,
            CharacteristicFormats.uint16,
            CharacteristicFormats.uint8,
            CharacteristicFormats.int,
            CharacteristicFormats.float,
        ]:
            if self.minValue is not None and new_val < self.minValue:
                raise FormatError(HapStatusCode.INVALID_VALUE)
            if self.maxValue is not None and self.maxValue < new_val:
                raise FormatError(HapStatusCode.INVALID_VALUE)
            if self.minStep is not None:
                tmp = new_val

                # if minValue is set, the steps count from this on
                if self.minValue is not None:
                    tmp -= self.minValue

                # use Decimal to calculate the module because it has not the precision problem as float...
                if Decimal(str(tmp)) % Decimal(str(self.minStep)) != 0:
                    raise FormatError(HapStatusCode.INVALID_VALUE)
            if self.valid_values is not None and new_val not in self.valid_values:
                raise FormatError(HapStatusCode.INVALID_VALUE)
            if self.valid_values_range is not None and not (
                self.valid_values_range[0] <= new_val <= self.valid_values_range[1]
            ):
                raise FormatError(HapStatusCode.INVALID_VALUE)

        if self.format == CharacteristicFormats.data:
            try:
                byte_data = base64.decodebytes(new_val.encode())
            except binascii.Error:
                raise FormatError(HapStatusCode.INVALID_VALUE)
            except Exception:
                raise FormatError(HapStatusCode.OUT_OF_RESOURCES)
            if self.maxDataLen < len(byte_data):
                raise FormatError(HapStatusCode.INVALID_VALUE)

        if self.format == CharacteristicFormats.string:
            if len(new_val) > self.maxLen:
                raise FormatError(HapStatusCode.INVALID_VALUE)

        return new_val

    def get_value(self):
        """
        This method returns the value of this characteristic. Permissions are checked first, then either the callback
        for getting the values is executed (execution time may vary) or the value is directly returned if not callback
        is given.

        :raises CharacteristicPermissionError: if the characteristic cannot be read
        :return: the value of the characteristic
        """
        if CharacteristicPermissions.paired_read not in self.perms:
            raise CharacteristicPermissionError(HapStatusCode.CANT_READ_WRITE_ONLY)
        return self.value

    def to_accessory_and_service_list(self):
        d = {
            "type": self.type,
            "iid": self.iid,
            "perms": self.perms,
            "format": self.format,
        }
        if CharacteristicPermissions.paired_read in self.perms:
            d["value"] = self._value
        if self.ev:
            d["ev"] = self.ev
        if self.description:
            d["description"] = self.description
        if self.unit:
            d["unit"] = self.unit
        if self.minValue is not None:
            d["minValue"] = self.minValue
        if self.maxValue is not None:
            d["maxValue"] = self.maxValue
        if self.minStep is not None:
            d["minStep"] = self.minStep
        if self.maxLen and self.format in [CharacteristicFormats.string]:
            d["maxLen"] = self.maxLen
        if self.valid_values is not None:
            d["valid-values"] = self.valid_values
        return d


def check_convert_value(val: str, char: Characteristic) -> Any:
    """
    Checks if the given value is of the given type or is convertible into the type. If the value is not convertible, a
    HomeKitTypeException is thrown.

    :param val: the original value
    :param char: the characteristic
    :return: the converted value
    :raises FormatError: if the input value could not be converted to the target type
    """

    if char.format == CharacteristicFormats.bool:
        try:
            val = strtobool(str(val))
        except ValueError:
            raise FormatError(f'"{val}" is no valid "{char.format}"!')

        # We have seen iPhone's sending 1 and 0 for True and False
        # This is in spec
        # It is also *required* for Ecobee Switch+ devices (as at Mar 2020)
        return 1 if val else 0

    if char.format in NUMBER_TYPES:
        try:
            val = Decimal(val)
        except ValueError:
            raise FormatError(f'"{val}" is no valid "{char.format}"!')

        if char.minValue is not None:
            val = max(Decimal(char.minValue), val)

        if char.maxValue is not None:
            val = min(Decimal(char.maxValue), val)

        # Honeywell T6 Pro cannot handle arbritary precision, the values we send
        # *must* respect minStep
        # See https://github.com/home-assistant/core/issues/37083
        if char.minStep is not None:
            with localcontext() as ctx:
                ctx.prec = 6

                # Python3 uses bankers rounding by default, so 28.5 rounds to 28, not 29.
                # This is surprising for most people
                ctx.rounding = ROUND_HALF_UP

                val = Decimal(val)
                offset = Decimal(char.minValue if char.minValue is not None else 0)
                min_step = Decimal(char.minStep)

                # We use to_integral_value() here rather than round as it respsects
                # ctx.rounding
                val = offset + (
                    ((val - offset) / min_step).to_integral_value() * min_step
                )

        if char.format in INTEGER_TYPES:
            val = int(val.to_integral_value())
        else:
            val = float(val)

    if char.format == CharacteristicFormats.data:
        try:
            base64.decodebytes(val.encode())
        except binascii.Error:
            raise FormatError(f'"{val}" is no valid "{char.format}"!')

    if char.format == CharacteristicFormats.tlv8:
        try:
            tmp_bytes = base64.decodebytes(val.encode())
            TLV.decode_bytes(tmp_bytes)
        except (binascii.Error, TlvParseException):
            raise FormatError(f'"{val}" is no valid "{char.format}"!')

    return val
