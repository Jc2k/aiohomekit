from aiohomekit.enum import EnumWithDescription


class EnumTest(EnumWithDescription):

    RED = 1, "The colour is red"
    BLUE = 2, "This colour is blue"


def test_value_isnt_tuple():
    assert EnumTest.RED.value == 1


def test_casting():
    assert EnumTest(1) == EnumTest.RED


def test_has_description():
    assert EnumTest.RED.description == "The colour is red"
    assert EnumTest(1).description == "The colour is red"
