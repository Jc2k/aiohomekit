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
