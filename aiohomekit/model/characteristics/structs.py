#
# Copyright 2020 aiohomekit team
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

from dataclasses import dataclass
from typing import Sequence

from aiohomekit.tlv8 import TLVStruct, tlv_entry, u8, u16

from .const import (
    AudioCodecValues,
    BitRateValues,
    CVOEnabledValues,
    PacketizationModeValues,
    ProfileIDValues,
    ProfileSupportLevelValues,
    SampleRateValues,
    SessionControlCommandValues,
    SRTPCryptoSuiteValues,
    StreamingStatusValues,
    VideoCodecTypeValues,
)


@dataclass
class StreamingStatus(TLVStruct):

    status: StreamingStatusValues = tlv_entry(1)


@dataclass
class SessionControl(TLVStruct):
    session: str = tlv_entry(1)
    command: SessionControlCommandValues = tlv_entry(2)


@dataclass
class SelectedVideoParameters(TLVStruct):
    pass


@dataclass
class SelectedAudioParameters(TLVStruct):
    pass


@dataclass
class SelectedRTPStreamConfiguration(TLVStruct):

    control: SessionControl = tlv_entry(1)
    video_params: SelectedVideoParameters = tlv_entry(2)
    audio_params: SelectedAudioParameters = tlv_entry(3)


@dataclass
class AudioCodecParameters(TLVStruct):

    audio_channels: u8 = tlv_entry(1)
    bit_rate: BitRateValues = tlv_entry(2)
    sample_rate: SampleRateValues = tlv_entry(3)
    rtp_time: u8 = tlv_entry(4)


@dataclass
class AudioCodecConfiguration(TLVStruct):

    codec: AudioCodecValues = tlv_entry(1)
    parameters: Sequence[AudioCodecParameters] = tlv_entry(2)


@dataclass
class SupportedAudioStreamConfiguration(TLVStruct):

    """
    UUID 00000115-0000-1000-8000-0026BB765291
    Type public.hap.characteristic.supported-audio-stream-configuration
    """

    config: Sequence[AudioCodecConfiguration] = tlv_entry(1)
    comfort_noise: u8 = tlv_entry(2)


@dataclass
class VideoCodecParameters(TLVStruct):
    profile_id: ProfileIDValues = tlv_entry(1)
    level: ProfileSupportLevelValues = tlv_entry(2)
    packetization_mode: PacketizationModeValues = tlv_entry(3)
    cvo_enabled: CVOEnabledValues = tlv_entry(4)
    cvo_id: u8 = tlv_entry(5)


@dataclass
class VideoAttrs(TLVStruct):
    width: u16 = tlv_entry(1)
    height: u16 = tlv_entry(2)
    fps: u8 = tlv_entry(3)


@dataclass
class VideoConfigConfiguration(TLVStruct):
    codec_type: VideoCodecTypeValues = tlv_entry(1)
    codec_params: Sequence[VideoCodecParameters] = tlv_entry(2)
    video_attrs: Sequence[VideoAttrs] = tlv_entry(3)


@dataclass
class SupportedVideoStreamConfiguration(TLVStruct):

    """
    UUID 00000114-0000-1000-8000-0026BB765291
    Type public.hap.characteristic.supported-video-stream-configuration
    """

    config: Sequence[VideoConfigConfiguration] = tlv_entry(1)


@dataclass
class SupportedRTPConfiguration(TLVStruct):

    """
    UUID 00000116-0000-1000-8000-0026BB765291
    Type public.hap.characteristic.supported-rtp-configuration
    """

    srtp_crypto_suite: SRTPCryptoSuiteValues = tlv_entry(2)
