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
from distutils.util import strtobool

from aiohomekit.exceptions import FormatError
from aiohomekit.model.characteristics import CharacteristicFormats
from aiohomekit.protocol.tlv import TLV, TlvParseException


def check_convert_value(val: str, target_type: str) -> int:
    """
    Checks if the given value is of the given type or is convertible into the type. If the value is not convertible, a
    HomeKitTypeException is thrown.
    :param val: the original value
    :param target_type: the target type of the conversion
    :return: the converted value
    :raises FormatError: if the input value could not be converted to the target type
    """
    if target_type == CharacteristicFormats.bool:
        try:
            val = strtobool(str(val))
        except ValueError:
            raise FormatError('"{v}" is no valid "{t}"!'.format(v=val, t=target_type))
    if target_type in [
        CharacteristicFormats.uint64,
        CharacteristicFormats.uint32,
        CharacteristicFormats.uint16,
        CharacteristicFormats.uint8,
        CharacteristicFormats.int,
    ]:
        try:
            val = int(val)
        except ValueError:
            raise FormatError('"{v}" is no valid "{t}"!'.format(v=val, t=target_type))
    if target_type == CharacteristicFormats.float:
        try:
            val = float(val)
        except ValueError:
            raise FormatError('"{v}" is no valid "{t}"!'.format(v=val, t=target_type))
    if target_type == CharacteristicFormats.data:
        try:
            base64.decodebytes(val.encode())
        except binascii.Error:
            raise FormatError('"{v}" is no valid "{t}"!'.format(v=val, t=target_type))
    if target_type == CharacteristicFormats.tlv8:
        try:
            tmp_bytes = base64.decodebytes(val.encode())
            TLV.decode_bytes(tmp_bytes)
        except (binascii.Error, TlvParseException):
            raise FormatError('"{v}" is no valid "{t}"!'.format(v=val, t=target_type))
    return val
