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
