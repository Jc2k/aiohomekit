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

from aiohomekit.model import Accessories
from aiohomekit.model.characteristics import CharacteristicsTypes
from aiohomekit.model.characteristics.const import (
    AudioCodecValues,
    BitRateValues,
    PacketizationModeValues,
    ProfileIDValues,
    ProfileSupportLevelValues,
    SampleRateValues,
    StreamingStatusValues,
    VideoCodecTypeValues,
)
from aiohomekit.model.characteristics.structs import (
    AudioCodecConfiguration,
    AudioCodecParameters,
    SupportedAudioStreamConfiguration,
    SupportedVideoStreamConfiguration,
    VideoAttrs,
    VideoCodecParameters,
    VideoConfigConfiguration,
)
from aiohomekit.model.services import ServicesTypes


def test_hue_bridge():
    a = Accessories.from_file("tests/fixtures/hue_bridge.json").aid(6623462389072572)
    assert a.name == "Hue dimmer switch"
    assert a.model == "RWL021"
    assert a.manufacturer == "Philips"
    assert a.serial_number == "6623462389072572"
    assert a.firmware_revision == "45.1.17846"

    service = a.services.first(service_type=ServicesTypes.ACCESSORY_INFORMATION)
    assert service.type_name == "accessory-information"

    char = next(iter(service.characteristics))
    assert char.iid == 37
    assert char.type_name == "name"
    assert char.perms == ["pr"]
    assert char.format == "string"
    assert char.value == "Hue dimmer switch"
    assert char.description == "Name"
    assert char.maxLen == 64

    assert service.has(char.type)


def test_idevices_switch():
    a = Accessories.from_file("tests/fixtures/idevices_switch.json").aid(1)
    assert a.name == "iDevices Switch"
    assert a.model == "IDEV0001"
    assert a.manufacturer == "iDevices LLC"
    assert a.serial_number == "00080685"
    assert a.firmware_revision == "1.2.1"

    service = a.services.first(service_type=ServicesTypes.ACCESSORY_INFORMATION)
    assert service.type_name == "accessory-information"

    char = next(iter(service.characteristics))
    assert char.iid == 2
    assert char.type_name == "name"
    assert char.perms == ["pr"]
    assert char.format == "string"
    assert char.value == "iDevices Switch"
    assert char.description == "Name"
    assert char.maxLen == 64

    assert service.has(char.type)


def test_linked_services():
    a = Accessories.from_file("tests/fixtures/hue_bridge.json").aid(6623462389072572)

    service = a.services.first(service_type=ServicesTypes.STATELESS_PROGRAMMABLE_SWITCH)
    assert len(service.linked) > 0
    assert service.linked[0].short_type == ServicesTypes.SERVICE_LABEL


def test_get_by_name():
    name = "Hue dimmer switch button 3"
    a = Accessories.from_file("tests/fixtures/hue_bridge.json").aid(6623462389072572)

    service = a.services.first(
        service_type=ServicesTypes.STATELESS_PROGRAMMABLE_SWITCH,
        characteristics={CharacteristicsTypes.NAME: name},
    )

    assert service[CharacteristicsTypes.NAME].value == name


def test_get_by_characteristic_types():
    name = "Hue dimmer switch button 3"

    a = Accessories.from_file("tests/fixtures/hue_bridge.json").aid(6623462389072572)

    service = a.services.first(
        service_type=ServicesTypes.STATELESS_PROGRAMMABLE_SWITCH,
        characteristics={CharacteristicsTypes.NAME: name},
    )

    char = service.characteristics.first(char_types=[CharacteristicsTypes.NAME])

    assert char.value == name


def test_get_by_linked():
    name = "Hue dimmer switch button 3"
    a = Accessories.from_file("tests/fixtures/hue_bridge.json").aid(6623462389072572)

    switch = a.services.first(
        service_type=ServicesTypes.STATELESS_PROGRAMMABLE_SWITCH,
        characteristics={CharacteristicsTypes.NAME: name},
    )

    service_label = a.services.first(parent_service=switch)
    assert service_label[CharacteristicsTypes.SERVICE_LABEL_NAMESPACE].value == 1

    switch = a.services.first(
        service_type=ServicesTypes.STATELESS_PROGRAMMABLE_SWITCH,
        characteristics={CharacteristicsTypes.NAME: name},
        child_service=service_label,
    )

    assert switch[CharacteristicsTypes.NAME].value == "Hue dimmer switch button 3"


def test_order_by():
    a = Accessories.from_file("tests/fixtures/hue_bridge.json").aid(6623462389072572)

    buttons = a.services.filter(
        service_type=ServicesTypes.STATELESS_PROGRAMMABLE_SWITCH,
        order_by=(CharacteristicsTypes.SERVICE_LABEL_INDEX, CharacteristicsTypes.NAME),
    )

    assert buttons[0].value(CharacteristicsTypes.SERVICE_LABEL_INDEX) == 1
    assert buttons[1].value(CharacteristicsTypes.SERVICE_LABEL_INDEX) == 2
    assert buttons[2].value(CharacteristicsTypes.SERVICE_LABEL_INDEX) == 3
    assert buttons[3].value(CharacteristicsTypes.SERVICE_LABEL_INDEX) == 4


def test_process_changes():
    accessories = Accessories.from_file("tests/fixtures/koogeek_ls1.json")

    on_char = accessories.aid(1).characteristics.iid(8)
    assert on_char.value is False

    accessories.process_changes({(1, 8): {"value": True}})

    assert on_char.value is True


def test_valid_vals_preserved():
    a = Accessories.from_file("tests/fixtures/aqara_gateway.json").aid(1)
    char = a.characteristics.iid(66307)
    assert char.valid_values == [1, 3, 4]


def test_build_update():
    name = "Hue dimmer switch button 3"

    a = Accessories.from_file("tests/fixtures/hue_bridge.json").aid(6623462389072572)

    service = a.services.first(
        service_type=ServicesTypes.STATELESS_PROGRAMMABLE_SWITCH,
        characteristics={CharacteristicsTypes.NAME: name},
    )

    payload = service.build_update({CharacteristicsTypes.NAME: "Fred"})

    assert payload == [(6623462389072572, 588410716196, "Fred")]


def test_build_update_minStep_clamping_lennox():
    a = Accessories.from_file("tests/fixtures/lennox_e30.json").aid(1)
    service = a.services.iid(100)

    assertions = [
        (27.23, 27.0),
        (27.6, 27.5),
        (27.26, 27.5),
        (27.9, 28.0),
    ]

    for left, right in assertions:
        payload = service.build_update({CharacteristicsTypes.TEMPERATURE_TARGET: left})
        assert payload == [(1, 104, right)]


def test_build_update_minStep_clamping_ecobee():
    a = Accessories.from_file("tests/fixtures/ecobee3.json").aid(1)
    service = a.services.iid(16)

    assertions = [
        (27.23, 27.2),
        (27.6, 27.6),
        (27.26, 27.3),
        (27.9, 27.9),
        (27.95, 28.0),
    ]

    for left, right in assertions:
        payload = service.build_update({CharacteristicsTypes.TEMPERATURE_TARGET: left})
        assert payload == [(1, 20, right)]


def test_build_update_minStep_clamping_synthetic():
    a = Accessories.from_file("tests/fixtures/synthetic_float_minstep.json")

    assertions = [
        # minStep 1
        (1, 27.2, 27.5),
        (1, 27.6, 27.5),
        (1, 27.9, 27.5),
        # minStep 2
        (2, 27.2, 26.5),
        (2, 28.2, 28.5),
        (2, 27.7, 28.5),
        # minStep 5
        (3, 27.2, 29.5),
        (3, 25.0, 24.5),
        (3, 28.3, 29.5),
        # no minStep
        (4, 27.2, 27.2),
        (4, 27.3, 27.3),
        (4, 27.7, 27.7),
        # minStep 1, no offset
        (5, 27.2, 27.0),
        (5, 27.6, 28.0),
        (5, 27.9, 28.0),
        # minStep 2, no offset
        (6, 27.2, 28.0),
        (6, 28.2, 28.0),
        (6, 27.7, 28.0),
        # minStep 5, no offset
        (7, 27.2, 25.0),
        (7, 25.0, 25.0),
        (7, 28.3, 30.0),
    ]

    for aid, left, right in assertions:
        service = a.aid(aid).services.iid(100)
        payload = service.build_update({CharacteristicsTypes.TEMPERATURE_TARGET: left})
        assert payload == [(aid, 104, right)]


def test_build_update_minStep_clamping_synthetic_int():
    a = Accessories.from_file("tests/fixtures/synthetic_float_minstep.json")

    assertions = [
        # minStep 1, int
        (8, 27.0, 27),
        (8, 27.5, 28),
        (8, 28.0, 28),
        (8, 28.5, 29),
        (8, 29.0, 29),
        (8, 29.5, 30),
        (8, 27.2, 27),
        (8, 27.6, 28),
        (8, 27.9, 28),
    ]

    for aid, left, right in assertions:
        service = a.aid(aid).services.iid(100)
        payload = service.build_update({CharacteristicsTypes.TEMPERATURE_TARGET: left})
        assert payload == [(aid, 104, right)]
        assert isinstance(payload[0][2], int)


def test_tlv8_struct():
    a = Accessories.from_file("tests/fixtures/home_assistant_bridge_camera.json")
    service = a.aid(2018094878).services.iid(11)

    streaming_status = service.value(CharacteristicsTypes.STREAMING_STATUS)
    assert streaming_status.status == StreamingStatusValues.AVAILABLE

    video_stream_config = service.value(
        CharacteristicsTypes.SUPPORTED_VIDEO_STREAM_CONFIGURATION
    )

    assert video_stream_config == SupportedVideoStreamConfiguration(
        config=[
            VideoConfigConfiguration(
                codec_type=VideoCodecTypeValues.H264,
                codec_params=[
                    VideoCodecParameters(
                        profile_id=ProfileIDValues.HIGH_PROFILE,
                        level=ProfileSupportLevelValues.FOUR,
                        packetization_mode=PacketizationModeValues.NON_INTERLEAVED_MODE,
                        cvo_enabled=None,
                        cvo_id=None,
                    )
                ],
                video_attrs=[VideoAttrs(width=1920, height=1080, fps=30)],
            )
        ]
    )

    audio_stream_config = service.value(
        CharacteristicsTypes.SUPPORTED_AUDIO_CONFIGURATION
    )

    assert audio_stream_config == SupportedAudioStreamConfiguration(
        config=[
            AudioCodecConfiguration(
                codec=AudioCodecValues.OPUS,
                parameters=[
                    AudioCodecParameters(
                        audio_channels=1,
                        bit_rate=BitRateValues.VARIABLE,
                        sample_rate=SampleRateValues.SIXTEEN_KHZ,
                        rtp_time=None,
                    )
                ],
            )
        ],
        comfort_noise=0,
    )


def test_tlv8_struct_re_encode():
    a = Accessories.from_file("tests/fixtures/camera.json")
    service = a.aid(1).services.iid(16)

    video_stream_config = service.value(
        CharacteristicsTypes.SUPPORTED_VIDEO_STREAM_CONFIGURATION
    )

    raw = base64.b64decode(
        "AcUBAQACHQEBAAAAAQEBAAABAQICAQAAAAIBAQAAAgECAwEAAwsBAoAHAgI4BAMBHgAAAwsBAgAFAgL"
        "AAwMBHgAAAwsBAgAFAgLQAgMBHgAAAwsBAgAEAgIAAwMBHgAAAwsBAoACAgLgAQMBHgAAAwsBAoACAg"
        "JoAQMBHgAAAwsBAuABAgJoAQMBHgAAAwsBAuABAgIOAQMBHgAAAwsBAkABAgLwAAMBHgAAAwsBAkABA"
        "gLwAAMBDwAAAwsBAkABAgK0AAMBHg=="
    )

    assert raw == video_stream_config.encode()
