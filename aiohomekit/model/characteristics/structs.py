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

from aiohomekit.tlv8 import TLVStruct, tlv_entry

from .const import SessionControlCommandValues, StreamingStatusValues


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
class VideoCodecParameters(TLVStruct):
    profile_id: int = tlv_entry(1)
    level: int = tlv_entry(2)
    packetization_mode: int = tlv_entry(3)
    cvo_enabled: int = tlv_entry(4)
    cvo_id: int = tlv_entry(5)


@dataclass
class VideoAttrs(TLVStruct):
    width: int = tlv_entry(1)
    height: int = tlv_entry(2)
    fps: int = tlv_entry(3)


@dataclass
class VideoConfigConfiguration(TLVStruct):
    codec_type: int = tlv_entry(1)
    codec_params: Sequence[VideoCodecParameters] = tlv_entry(2)
    video_attrs: VideoAttrs = tlv_entry(3)


@dataclass
class SupportedVideoStreamConfiguration(TLVStruct):

    """
    UUID 00000114-0000-1000-8000-0026BB765291
    Type public.hap.characteristic.supported-video-stream-configuration
    """

    config: Sequence[VideoConfigConfiguration] = tlv_entry(1)
