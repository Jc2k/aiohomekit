import enum


class CurrentMediaStateValues(enum.IntEnum):
    """States that a TV can be."""

    PLAYING = 0
    PAUSED = 1
    STOPPED = 2


class TargetMediaStateValues(enum.IntEnum):
    """States that a TV can be set to."""

    PLAY = 0
    PAUSE = 1
    STOP = 2


class RemoteKeyValues(enum.IntEnum):
    """Keys that can be send using the Remote Key characteristic."""

    REWIND = 0
    FAST_FORWARD = 1
    NEXT_TRACK = 2
    PREVIOUS_TRACK = 3
    ARROW_UP = 4
    ARROW_DOWN = 5
    ARROW_LEFT = 6
    ARROW_RIGHT = 7
    SELECT = 8
    BACK = 9
    EXIT = 10
    PLAY_PAUSE = 11
    INFORMATION = 15


class InputEventValues(enum.IntEnum):
    """Types of button press for CharacteristicsTypes.INPUT_EVENT."""

    SINGLE_PRESS = 0
    DOUBLE_PRESS = 1
    LONG_PRESS = 2


class HeatingCoolingCurrentValues(enum.IntEnum):
    """What is a thermostat currently doing."""

    IDLE = 0
    HEATING = 1
    COOLING = 2


class HeatingCoolingTargetValues(enum.IntEnum):
    """What is the current 'goal' for the thermostat."""

    OFF = 0
    HEAT = 1
    COOL = 2
    AUTO = 3


class InUseValues(enum.IntEnum):
    """Whether or not something is in use."""

    NOT_IN_USE = 0
    IN_USE = 1


class IsConfiguredValues(enum.IntEnum):
    """Whether or not something is configured."""

    NOT_CONFIGURED = 0
    CONFIGURED = 1


class ProgramModeValues(enum.IntEnum):
    """Whether or not a program is set."""

    NO_PROGRAM_SCHEDULED = 0
    PROGRAM_SCHEDULED = 1
    PROGRAM_SCHEDULED_MANUAL_MODE = 2


class ValveTypeValues(enum.IntEnum):
    """The type of valve."""

    GENERIC_VALVE = 0
    IRRIGATION = 1
    SHOWER_HEAD = 2
    WATER_FAUCET = 3


class ActivationStateValues(enum.IntEnum):
    """Possible values for the current status of an accessory.
    https://developer.apple.com/documentation/homekit/hmcharacteristicvalueactivationstate"""

    INACTIVE = 0
    ACTIVE = 1


class SwingModeValues(enum.IntEnum):
    """Possible values for fan movement.
    https://developer.apple.com/documentation/homekit/hmcharacteristicvalueswingmode"""

    DISABLED = 0
    ENABLED = 1


class CurrentHeaterCoolerStateValues(enum.IntEnum):
    """Possible values for the current state of a device that heats or cools.
    https://developer.apple.com/documentation/homekit/hmcharacteristicvaluecurrentheatercoolerstate"""

    INACTIVE = 0
    IDLE = 1
    HEATING = 2
    COOLING = 3


class TargetHeaterCoolerStateValues(enum.IntEnum):
    """Possible values for the target state of a device that heats or cools.
    https://developer.apple.com/documentation/homekit/hmcharacteristicvaluetargetheatercoolerstate"""

    AUTOMATIC = 0
    HEAT = 1
    COOL = 2


class StreamingStatusValues(enum.IntEnum):
    """The current streaming state of a camera."""

    AVAILABLE = 0
    IN_USE = 1
    UNAVAILABLE = 2


class SessionControlCommandValues(enum.IntEnum):
    """Session control commands."""

    END_SESSION = 0
    START_SESSION = 1
    SUSPEND_SESSION = 2
    RESUME_SESSION = 3
    RECONFIGURE_SESSION = 4


class VideoCodecTypeValues(enum.IntEnum):

    H264 = 0


class ProfileIDValues(enum.IntEnum):

    """
    The type of H.264 profile used.

    3-255 are vendor specific.
    """

    CONTRAINED_BASELINE_PROFILE = 0
    MAIN_PROFILE = 1
    HIGH_PROFILE = 2


class ProfileSupportLevelValues(enum.IntEnum):

    """
    3-255 are reserved by Apple.
    """

    THREE_ONE = 0
    THREE_TWO = 1
    FOUR = 2


class PacketizationModeValues(enum.IntEnum):
    """
    1 - 255 are reserved by Apple.
    """

    NON_INTERLEAVED_MODE = 0


class CVOEnabledValues(enum.IntEnum):

    NOT_SUPPORTED = 0
    SUPPORTED = 1


class AudioCodecValues(enum.IntEnum):

    """
    7-255 reserved for Apple.
    """

    AAC_ELD = 2
    OPUS = 3
    AMR = 5
    AMR_WB = 6


class BitRateValues(enum.IntEnum):

    VARIABLE = 0
    CONSTANT = 1


class SampleRateValues(enum.IntEnum):

    EIGHT_KHZ = 0
    SIXTEEN_KHZ = 1
    TWENTY_FOUR_KHZ = 2


class SRTPCryptoSuiteValues(enum.IntEnum):

    AES_CM_128_HMAC_SHA1_80 = 0
    AES_256_CM_HMAC_SHA1_80 = 1
    DISABLED = 2
