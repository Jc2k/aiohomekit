import struct

from aiohomekit.controller.coap.structs import (
    Pdu09Accessory,
    Pdu09AccessoryContainer,
    Pdu09Characteristic,
    Pdu09CharacteristicContainer,
    Pdu09Database,
    Pdu09Service,
    Pdu09ServiceContainer,
)

database_nanoleaf_bulb = bytes.fromhex(
    """
18ff19ff1a02010016ff15f10702010006013e100014e61314\
050202000401140a0220000c070100002701000000001314050203000401\
200a0210000c071900002701000000001314050204000401210a0210000c\
071900002701000000001314050205000401230a0210000c071900002701\
000000001314050206000401300a0210000c071900002701000000001314\
050207000401520a0210000c071900002701000000001314050208000401\
530a0210000c0719000027010000000013230502090004103b94f9856afd\
c3ba40437fac1188ab340a0250000c07190000270100000000131505020a\
00040220020a0250000c071b0000270100000000153d18ff070219ff1000\
0601a20f16ff0204001000142e1314050211000401a50a0210000c071b00\
002701000000001314050212000401370a0210000c071900002701000000\
001569070220000601551000145e13140502220004014c0a0203000c071b\
000027010000000013140502230004014e0a0203000c071b000027010000\
000013140502240004014f0a0201000c0704000027010000000013140502\
25000401500a0230000c071b000027010000000015ff070230000601430f\
020100100014ff1314050231000401a50a0210000c071b00002701000000\
001314050232000401230a0210000c071900002701000000001314050233\
000401250a02b0030c18ff0701000019ff270100000000131e16ff050237\
000401ce0a02b0030c07080000270100000d0899000000d6010000000013\
1e050234000401080a02b0030c071000ad270100000d0800000000640000\
000000132305023c000410bdeeeece71000fa1374da1cf02198ea20a0270\
000c071b0000270100000000131505023900040244010a0210000c071b00\
00270100000000131505023800040243010a0230000c071b000027010000\
0000131905023a0004024b020a15620290030c07040000270100000d0200\
14510200001324050235000401130a02b0030c07140063270100000d0800\
0000000000b4430e040000803f000013240502360004012f0a0218ffb003\
0c07140019ffad270100000d0800000016ff000000c8420e040000803f00\
0015ab07027000060201071000149f1314050271000401a50a0210000c07\
1b0000270100000000131505027400040206070a0210000c071900002701\
00000000131b05027300040202070a0210000c07060000270100000d0400\
001f000000131b05027500040203070a0290030c07060000270100000d04\
00007f00000013150502760004022b020a0210000c070100002701000000\
00131505027700040204070a0230000c071b000027010000000015770702\
000a060239021000146b13140502040a0401a50a0210000c071b00002701\
00000000131f0502010a04023a184e020a0210000c070819440000270100\
000d08000000001636ffffff03000013150502020a04023c020a0211000c\
071b000027010000000013150502050a04024a020a0290030c0708000027\
010000"""
)


def test_coap_pdu09_encode_1():
    c_identity = Pdu09CharacteristicContainer(
        Pdu09Characteristic(
            0x14, 2, 0x0200, b"\x01\x00\x00\x27\x01\x00\x00", None, None, None, None
        )
    )
    s_accessory_information = Pdu09ServiceContainer(
        Pdu09Service(0x3E, 1, [c_identity], None, b"")
    )
    a_light = Pdu09AccessoryContainer(Pdu09Accessory(1, [s_accessory_information]))
    database = Pdu09Database([a_light])

    exp_c_identity = (
        # characteristic tag + length
        b"\x13\x23"
        # type TLV
        + b"\x04\x10\x14"
        + b"\x00" * 15
        # instance id TLV
        + b"\x05\x02\x02\x00"
        # properties TLV
        + b"\x0A\x02\x00\x02"
        # presentation format TLV
        + b"\x0C\x07\x01\x00\x00\x27\x01\x00\x00"
    )
    assert c_identity.encode() == exp_c_identity

    exp_s_accessory_information = (
        # service tag + length
        b"\x15\x3D"
        # type TLV
        + b"\x06\x10\x3E"
        + b"\x00" * 15
        # instance id TLV
        + b"\x07\x02\x01\x00"
        # characteristics container TLV
        + b"\x14\x25"
        # characteristics
        + exp_c_identity
    )
    assert s_accessory_information.encode() == exp_s_accessory_information

    exp_a_light = (
        # accessory tag + length
        b"\x19\x45"
        # instance id TLV
        + b"\x1A\x02\x01\x00"
        # services container TLV
        + b"\x16\x3F"
        # services
        + exp_s_accessory_information
    )
    assert a_light.encode() == exp_a_light

    exp_database = b"\x18\x47" + exp_a_light
    assert database.encode() == exp_database


def test_coap_pdu09_decode_1():
    info = Pdu09Database.decode(database_nanoleaf_bulb)

    # accessory tests
    assert len(info._accessories) == 1

    lightbulb_accessory = info._accessories[0].accessory

    assert lightbulb_accessory.instance_id == 1
    assert lightbulb_accessory.find_characteristic_by_iid(51) is not None
    assert lightbulb_accessory.find_service_by_type(0x43) is not None
    assert (
        lightbulb_accessory.find_service_characteristic_by_type(0x0701, 0x022B)
        is not None
    )
    assert lightbulb_accessory.find_characteristic_by_iid(999) is None
    assert lightbulb_accessory.find_service_by_type(999) is None
    assert lightbulb_accessory.find_service_characteristic_by_type(999, 999) is None

    # service tests
    services = lightbulb_accessory.services

    assert len(services) == 6
    assert services[0].instance_id == 1
    assert services[1].instance_id == 16
    assert services[2].instance_id == 32
    assert services[3].instance_id == 48
    assert services[4].instance_id == 112
    assert services[5].instance_id == 2560

    lightbulb_service = services[3]

    assert lightbulb_service.find_characteristic_by_iid(51) is not None
    assert lightbulb_service.find_characteristic_by_type(0x25) is not None
    assert lightbulb_service.find_characteristic_by_iid(999) is None
    assert lightbulb_service.find_characteristic_by_type(999) is None

    assert lightbulb_service.type == 0x43
    assert lightbulb_service.properties == 0x0001
    assert lightbulb_service.linked_services == []

    # characteristic tests
    # get a characteristic whose type is string
    name_char = lightbulb_service.characteristics[1]

    assert name_char.data_type_str == "string"

    name_char.raw_value = b"\x41\x42\x43\x44"
    assert name_char.value == "ABCD"

    name_char.value = "EFGH"
    assert name_char.raw_value == b"\x45\x46\x47\x48"

    on_off_char = lightbulb_service.characteristics[2]

    assert on_off_char.type == 0x25
    assert on_off_char.instance_id == 51
    assert on_off_char.properties == 0x03B0
    assert on_off_char.supports_broadcast_notify
    assert on_off_char.notifies_events_in_disconnected_state
    assert on_off_char.notifies_events_in_connected_state
    assert not on_off_char.hidden_from_user
    assert on_off_char.supports_secure_writes
    assert on_off_char.supports_secure_reads
    assert not on_off_char.requires_hap_characteristic_timed_write_procedure
    assert not on_off_char.supports_additional_authorization_data
    assert not on_off_char.supports_write
    assert not on_off_char.supports_read
    assert on_off_char.presentation_format == b"\x01\x00\x00\x27\x01\x00\x00"
    assert on_off_char.data_type_str == "bool"
    assert on_off_char.data_unit_str == "unitless"
    assert on_off_char.valid_range is None
    assert on_off_char.step_value is None
    assert on_off_char.valid_values is None
    assert on_off_char.valid_values_range is None

    on_off_char.value = True
    assert on_off_char.raw_value == b"\x01"

    on_off_char.raw_value = b"\x00"
    assert on_off_char.value is False

    on_off_char_dict = on_off_char.to_dict()
    assert on_off_char_dict["type"] == "25"
    assert on_off_char_dict["iid"] == 51
    assert "pr" in on_off_char_dict["perms"]
    assert "pw" in on_off_char_dict["perms"]
    assert "ev" in on_off_char_dict["perms"]
    assert "aa" not in on_off_char_dict["perms"]
    assert "tw" not in on_off_char_dict["perms"]
    assert "hd" not in on_off_char_dict["perms"]
    assert on_off_char_dict["format"] == "bool"
    assert "unit" not in on_off_char_dict
    assert on_off_char_dict["value"] is False

    # get a characteristic whose type is int
    brightness_char = lightbulb_service.characteristics[4]

    assert brightness_char.data_type_str == "int"

    brightness_char.value = 100
    assert brightness_char.raw_value == struct.pack("<l", 100)

    brightness_char.raw_value = b"\x32\x00\x00\x00"
    assert brightness_char.value == 50

    # get a characteristic whose type is data
    nanoleaf_char = lightbulb_service.characteristics[5]

    assert nanoleaf_char.data_type_str == "data"

    # get a characteristic whose type is float
    hue_char = lightbulb_service.characteristics[9]

    assert hue_char.type == 0x13
    assert hue_char.data_type_str == "float"
    assert hue_char.data_unit_str == "arcdegrees"

    hue_char.value = 360.0
    assert hue_char.raw_value == struct.pack("<f", 360.0)

    hue_char.raw_value = b"\x00\x80\x9D\x43"
    assert hue_char.value == 315.0

    # get a characteristic whose unit is percentage
    saturation_char = lightbulb_service.characteristics[10]

    assert saturation_char.data_unit_str == "percentage"
