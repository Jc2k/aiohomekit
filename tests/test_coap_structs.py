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
from aiohomekit.model import Accessory

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

database_schlage_encode_plus = bytes.fromhex(
    "18ff19ff1a02010016ff15ff0702010006013e100014ff1314050202000401140a0220000c070100002701000000001314050203000401200a0210000c071900002701000000001314050204000401210a0210000c071900002701000000001314050205000401230a0210000c071900002701000000001314050206000401300a0210000c071900002701000000001314050207000401520a0290010c071900002701000000001314050208000401530a0210000c0719000027010000000013230502090004103b94f9856afdc3ba40437fac1188ab340a0250000c07190000270100000000131505020a00040220020a0210000c071b0000270100000000131518ff050219ff0b0004026c0216ff0a02150b10000c071b0000270100000000153d070210000601a20f0204001000142e1314050211000401a50a0210000c071b00002701000000001314050212000401370a0210000c071900002701000000001569070220000601551000145e13140502220004014c0a0203000c071b000027010000000013140502230004014e0a0203000c071b000027010000000013140502240004014f0a0201000c070400002701000000001314050225000401500a0230000c071b00002701000000001577070200200601450f020100100250fa14661314050201200401a50a0210000c071b000027010000000013140502022004012318ff0a02100019ff0c0719000027010016ff00000013180502032004011d0a0290070c07040000270100000d020003000013180502042004011e0a02b8030c07040000270100000d020001000015c1070250fa0601440f0200001002002014b01314050251fa0401a50a0210000c071b00002701000000001314050252fa0401190a0228000c071b00002701000000001314050253fa0401370a0210000c071900002701000000001314050254fa04011f0a0210000c071b00002701000000001314050255fa0401050a0230000c07010000270100000000131e050256fa04011a0a0230000c07080003270100000d08000000002c01000000001314050257fa0418ff01010a02300019ff0c07010000270100000016ff0015750702e0000601961000146a13140502e4000401230a0210000c0719000027010000000013180502e1000401680a0290030c070400ad270100000d020064000013180502e20004018f0a0290030c07040000270100000d020002000013180502e3000401790a0290030c07040000270100000d020001000015a707020040060260020f0200001002002014951314050201400401a50a0210000c071b00002701000000001314050202400401230a0210000c07190000270100000000131505020340040261020a0210000c071b0000270100000000131505020440040262020a0230000c071b00002718ff010000000013150519ff020540040263020a0290030c16ff070600002701000000001318050206400401b00a02b0030c07040000270100000d0200010000158b07020050060266020f0200001002002014791314050201500401a50a0210000c071b00002701000000001314050202500401230a0210000c07190000270100000000131505020350040265020a0210000c071b0000270100000000131505020450040264020a0230000c071b0000270100000000131505020550040263020a0290030c0706000027010000000015ab07027000060201071000149f1314050271000401a50a0210000c071b0000270100000000131505027400040206070a0218ff10000c0719000027010019ff000000131b05027300040202070a16ff0210000c07060000270100000d0400001f000000131b05027500040203070a0290030c07060000270100000d0400007f00000013150502760004022b020a0210000c07010000270100000000131505027700040204070a0230000c071b000027010000000015ff070200fa0610fbbd01d36ca4e69803413f4a73ee0d7f0f020200100014ff1314050201fa0401a50a0250000c071b00002701000000001314050202fa0401230a0250000c071900002701000000001323050203fa0410f661dd50665f98b25649db585368ff440a0260000c071b00002701000000001327050204fa0418ff102b3a646b534c8c917e4f6f19ffdc0fc468cf0a0270000c07040000270116ff00000d02000300001327050205fa04108b71f9387c15b7b6774e4545b8c258400a0270000c07040000270100000d02010500001327050206fa0410df70e0ad6315ccb5794f6463b5f498b40a0270000c07040000270100000d02000100001323050207fa0410b515ffed798bb1c0e0ba204bd38dd27aaeaf0a0260000c071b000027010000000014ff1323050208fa0410a079f10b1ba2f189ad4c08c5c61ed9870a0250000c071b00002701000000001335050209fa0410669a0c200008aca3e3117ff541263e4c0a0250000c070a0003270100000d10000000000000000018ff2b1be2f40000000000001327050219ff0afa0410669a0c200008aca3e31128f6906916ffc2ee0a0270000c07040000270100000d0204080000132305020bfa0410c4a9b3cbec424db2234163399e3bdebc0a0250000c071b0000270100000000132305020cfa04100ab5b678c2cec4abe711a294803c89580a0270000c071b0000270100000000132305020dfa159e0410e2fdc70384a5df890147f25655e1167a0a0250000c071900002701000000147c00132705020efa04104a7903839800b2875b46afc40e237f5d0a0260000c07040000270100000d0200010000132705020ffa041010ba0c749c24b79e074d13ee278daf1e0a0250000c070400002718ff0100000d02000100001323050210fa0419ff10ba300e9d017c51bdd946c7de1586b2fe0a027016ff000c070100002701000000001582070220fa0610d0332b784e9a6498aa46cb14ec453f880f020200100014641314050221fa0401a50a0250000c071b00002701000000001323050222fa04103008daafd25c088c124801e0982900260a0250000c071b00002701000000001323050223fa041096372bf31207d4bbb94b50cd780c53ff0a0250000c071b000027010000000015d0070230fa0610bd17318238da1c98a94bde94aa436b1f0f020200100014b21314050231fa0401a50a0250000c071b00002701000000001323050232fa0410fe871530a118ffa4f7a77f4a5b6999878d040a0250000c070619ff00002701000000001323050233fa04106cc4673a073816ffadb0894fa795fdc7b7660a0250000c071b00002701000000001323050234fa04108f1f7f4204fa6a978c4331923ffc7e500a0250000c070600002701000000001323050235fa0410900c60b0ea9a0fabad4b82081957c11d0a0250000c0704000027010000000015770702000a060239021000146b13140502040a0401a50a0210000c071b0000270100000000131f0502010a04023a020a0210000c07080000270100000d0800000000ffffff03000013150502020a04023c020a0210000c071b000027010000000013150502050a04024a0218ff0a0290030c07080000270100000000159e0702f019ff00060229011000149213140502f1000401a50a0210000c0716ff1b000027010000000013150502f200040230010a0210000c071b000027010000000013150502f300040231010a0230000c071b000027010000000013140502f4000401370a0210000c0719000027010000000013150502f500040238010a0230000c071b000027010000000013150502f600040239010a0290010c071b000027010000000015540702000f060236021000144813140502010f0401a50a0210000c071b000027010000000013150502020f040234020a0290010c071b000027010000000013150502030f040235020a18370290010c071b000027010000000015230702d0000602191f37021000141713150502d100040238020a0210000c071b0000271603010000"
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
        + b"\x0a\x02\x00\x02"
        # presentation format TLV
        + b"\x0c\x07\x01\x00\x00\x27\x01\x00\x00"
    )
    assert c_identity.encode() == exp_c_identity

    exp_s_accessory_information = (
        # service tag + length
        b"\x15\x3d"
        # type TLV
        + b"\x06\x10\x3e"
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
        + b"\x1a\x02\x01\x00"
        # services container TLV
        + b"\x16\x3f"
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

    hue_char.raw_value = b"\x00\x80\x9d\x43"
    assert hue_char.value == 315.0

    # get a characteristic whose unit is percentage
    saturation_char = lightbulb_service.characteristics[10]

    assert saturation_char.data_unit_str == "percentage"


def test_coap_pdu09_decode_2():
    info = Pdu09Database.decode(database_schlage_encode_plus)
    accessory = Accessory.create_from_dict(info.to_dict()[0])
    import json

    print(json.dumps(accessory.to_accessory_and_service_list()))
    assert accessory.to_accessory_and_service_list() == {
        "aid": 1,
        "services": [
            {
                "iid": 1,
                "type": "0000003E-0000-1000-8000-0026BB765291",
                "characteristics": [
                    {
                        "type": "00000014-0000-1000-8000-0026BB765291",
                        "iid": 2,
                        "perms": ["pw"],
                        "format": "bool",
                        "description": "Identify",
                    },
                    {
                        "type": "00000020-0000-1000-8000-0026BB765291",
                        "iid": 3,
                        "perms": ["pr"],
                        "format": "string",
                        "value": "",
                        "description": "Manufacturer",
                        "maxLen": 64,
                    },
                    {
                        "type": "00000021-0000-1000-8000-0026BB765291",
                        "iid": 4,
                        "perms": ["pr"],
                        "format": "string",
                        "value": "",
                        "description": "Model",
                        "maxLen": 64,
                    },
                    {
                        "type": "00000023-0000-1000-8000-0026BB765291",
                        "iid": 5,
                        "perms": ["pr"],
                        "format": "string",
                        "value": "",
                        "description": "Name",
                        "maxLen": 64,
                    },
                    {
                        "type": "00000030-0000-1000-8000-0026BB765291",
                        "iid": 6,
                        "perms": ["pr"],
                        "format": "string",
                        "value": "",
                        "description": "Serial Number",
                        "maxLen": 64,
                    },
                    {
                        "type": "00000052-0000-1000-8000-0026BB765291",
                        "iid": 7,
                        "perms": ["pr", "ev"],
                        "format": "string",
                        "value": "",
                        "description": "Firmware Revision",
                        "maxLen": 64,
                    },
                    {
                        "type": "00000053-0000-1000-8000-0026BB765291",
                        "iid": 8,
                        "perms": ["pr"],
                        "format": "string",
                        "value": "",
                        "description": "Hardware Revision",
                        "maxLen": 64,
                    },
                    {
                        "type": "34AB8811-AC7F-4340-BAC3-FD6A85F9943B",
                        "iid": 9,
                        "perms": ["pr", "hd"],
                        "format": "string",
                        "value": "",
                        "maxLen": 64,
                    },
                    {
                        "type": "00000220-0000-1000-8000-0026BB765291",
                        "iid": 10,
                        "perms": ["pr"],
                        "format": "data",
                        "value": None,
                    },
                    {
                        "type": "0000026C-0000-1000-8000-0026BB765291",
                        "iid": 11,
                        "perms": ["pr"],
                        "format": "data",
                        "value": None,
                    },
                ],
            },
            {
                "iid": 16,
                "type": "000000A2-0000-1000-8000-0026BB765291",
                "characteristics": [
                    {
                        "type": "000000A5-0000-1000-8000-0026BB765291",
                        "iid": 17,
                        "perms": ["pr"],
                        "format": "data",
                        "value": None,
                    },
                    {
                        "type": "00000037-0000-1000-8000-0026BB765291",
                        "iid": 18,
                        "perms": ["pr"],
                        "format": "string",
                        "value": "",
                        "description": "Version",
                        "maxLen": 64,
                    },
                ],
            },
            {
                "iid": 32,
                "type": "00000055-0000-1000-8000-0026BB765291",
                "characteristics": [
                    {
                        "type": "0000004C-0000-1000-8000-0026BB765291",
                        "iid": 34,
                        "perms": [],
                        "format": "data",
                        "description": "Pair Setup",
                    },
                    {
                        "type": "0000004E-0000-1000-8000-0026BB765291",
                        "iid": 35,
                        "perms": [],
                        "format": "data",
                        "description": "Pair Verify",
                    },
                    {
                        "type": "0000004F-0000-1000-8000-0026BB765291",
                        "iid": 36,
                        "perms": [],
                        "format": "int",
                        "description": "Pairing Features",
                    },
                    {
                        "type": "00000050-0000-1000-8000-0026BB765291",
                        "iid": 37,
                        "perms": ["pr", "pw"],
                        "format": "data",
                        "value": None,
                        "description": "Pairing Pairings",
                    },
                ],
            },
            {
                "iid": 8192,
                "type": "00000045-0000-1000-8000-0026BB765291",
                "characteristics": [
                    {
                        "type": "000000A5-0000-1000-8000-0026BB765291",
                        "iid": 8193,
                        "perms": ["pr"],
                        "format": "data",
                        "value": None,
                    },
                    {
                        "type": "00000023-0000-1000-8000-0026BB765291",
                        "iid": 8194,
                        "perms": ["pr"],
                        "format": "string",
                        "value": "",
                        "description": "Name",
                        "maxLen": 64,
                    },
                    {
                        "type": "0000001D-0000-1000-8000-0026BB765291",
                        "iid": 8195,
                        "perms": ["pr", "ev"],
                        "format": "int",
                        "value": 3,
                        "description": "Lock Current State",
                        "minValue": 0,
                        "maxValue": 3,
                    },
                    {
                        "type": "0000001E-0000-1000-8000-0026BB765291",
                        "iid": 8196,
                        "perms": ["pr", "pw", "ev", "tw"],
                        "format": "int",
                        "value": 1,
                        "description": "Lock Target State",
                        "minValue": 0,
                        "maxValue": 1,
                    },
                ],
                "linked": [64080],
            },
            {
                "iid": 64080,
                "type": "00000044-0000-1000-8000-0026BB765291",
                "characteristics": [
                    {
                        "type": "000000A5-0000-1000-8000-0026BB765291",
                        "iid": 64081,
                        "perms": ["pr"],
                        "format": "data",
                        "value": None,
                    },
                    {
                        "type": "00000019-0000-1000-8000-0026BB765291",
                        "iid": 64082,
                        "perms": ["pw", "tw"],
                        "format": "data",
                        "description": "Lock Control Point",
                    },
                    {
                        "type": "00000037-0000-1000-8000-0026BB765291",
                        "iid": 64083,
                        "perms": ["pr"],
                        "format": "string",
                        "value": "",
                        "description": "Version",
                        "maxLen": 64,
                    },
                    {
                        "type": "0000001F-0000-1000-8000-0026BB765291",
                        "iid": 64084,
                        "perms": ["pr"],
                        "format": "data",
                        "value": None,
                        "description": "Logs",
                    },
                    {
                        "type": "00000005-0000-1000-8000-0026BB765291",
                        "iid": 64085,
                        "perms": ["pr", "pw"],
                        "format": "bool",
                        "value": False,
                        "description": "Audio Feedback",
                    },
                    {
                        "type": "0000001A-0000-1000-8000-0026BB765291",
                        "iid": 64086,
                        "perms": ["pr", "pw"],
                        "format": "int",
                        "value": 300,
                        "description": "Lock Management Auto Security Timeout",
                        "unit": "seconds",
                        "minValue": 0,
                        "maxValue": 300,
                    },
                    {
                        "type": "00000001-0000-1000-8000-0026BB765291",
                        "iid": 64087,
                        "perms": ["pr", "pw"],
                        "format": "bool",
                        "value": False,
                        "description": "Administrator Only Access",
                    },
                ],
            },
            {
                "iid": 224,
                "type": "00000096-0000-1000-8000-0026BB765291",
                "characteristics": [
                    {
                        "type": "00000023-0000-1000-8000-0026BB765291",
                        "iid": 228,
                        "perms": ["pr"],
                        "format": "string",
                        "value": "",
                        "description": "Name",
                        "maxLen": 64,
                    },
                    {
                        "type": "00000068-0000-1000-8000-0026BB765291",
                        "iid": 225,
                        "perms": ["pr", "ev"],
                        "format": "int",
                        "value": 100,
                        "description": "Battery Level",
                        "unit": "percentage",
                        "minValue": 0,
                        "maxValue": 100,
                        "minStep": 1,
                    },
                    {
                        "type": "0000008F-0000-1000-8000-0026BB765291",
                        "iid": 226,
                        "perms": ["pr", "ev"],
                        "format": "int",
                        "value": 2,
                        "description": "Charging State",
                        "minValue": 0,
                        "maxValue": 2,
                    },
                    {
                        "type": "00000079-0000-1000-8000-0026BB765291",
                        "iid": 227,
                        "perms": ["pr", "ev"],
                        "format": "int",
                        "value": 1,
                        "description": "Status Low Battery",
                        "minValue": 0,
                        "maxValue": 1,
                    },
                ],
            },
            {
                "iid": 16384,
                "type": "00000260-0000-1000-8000-0026BB765291",
                "characteristics": [
                    {
                        "type": "000000A5-0000-1000-8000-0026BB765291",
                        "iid": 16385,
                        "perms": ["pr"],
                        "format": "data",
                        "value": None,
                    },
                    {
                        "type": "00000023-0000-1000-8000-0026BB765291",
                        "iid": 16386,
                        "perms": ["pr"],
                        "format": "string",
                        "value": "",
                        "description": "Name",
                        "maxLen": 64,
                    },
                    {
                        "type": "00000261-0000-1000-8000-0026BB765291",
                        "iid": 16387,
                        "perms": ["pr"],
                        "format": "data",
                        "value": None,
                    },
                    {
                        "type": "00000262-0000-1000-8000-0026BB765291",
                        "iid": 16388,
                        "perms": ["pr", "pw"],
                        "format": "data",
                        "value": None,
                    },
                    {
                        "type": "00000263-0000-1000-8000-0026BB765291",
                        "iid": 16389,
                        "perms": ["pr", "ev"],
                        "format": "int",
                        "value": 0,
                    },
                    {
                        "type": "000000B0-0000-1000-8000-0026BB765291",
                        "iid": 16390,
                        "perms": ["pr", "pw", "ev"],
                        "format": "int",
                        "value": 1,
                        "description": "Active",
                        "minValue": 0,
                        "maxValue": 1,
                    },
                ],
            },
            {
                "iid": 20480,
                "type": "00000266-0000-1000-8000-0026BB765291",
                "characteristics": [
                    {
                        "type": "000000A5-0000-1000-8000-0026BB765291",
                        "iid": 20481,
                        "perms": ["pr"],
                        "format": "data",
                        "value": None,
                    },
                    {
                        "type": "00000023-0000-1000-8000-0026BB765291",
                        "iid": 20482,
                        "perms": ["pr"],
                        "format": "string",
                        "value": "",
                        "description": "Name",
                        "maxLen": 64,
                    },
                    {
                        "type": "00000265-0000-1000-8000-0026BB765291",
                        "iid": 20483,
                        "perms": ["pr"],
                        "format": "data",
                        "value": None,
                    },
                    {
                        "type": "00000264-0000-1000-8000-0026BB765291",
                        "iid": 20484,
                        "perms": ["pr", "pw"],
                        "format": "data",
                        "value": None,
                    },
                    {
                        "type": "00000263-0000-1000-8000-0026BB765291",
                        "iid": 20485,
                        "perms": ["pr", "ev"],
                        "format": "int",
                        "value": 0,
                    },
                ],
            },
            {
                "iid": 112,
                "type": "00000701-0000-1000-8000-0026BB765291",
                "characteristics": [
                    {
                        "type": "000000A5-0000-1000-8000-0026BB765291",
                        "iid": 113,
                        "perms": ["pr"],
                        "format": "data",
                        "value": None,
                    },
                    {
                        "type": "00000706-0000-1000-8000-0026BB765291",
                        "iid": 116,
                        "perms": ["pr"],
                        "format": "string",
                        "value": "",
                        "maxLen": 64,
                    },
                    {
                        "type": "00000702-0000-1000-8000-0026BB765291",
                        "iid": 115,
                        "perms": ["pr"],
                        "format": "int",
                        "value": 31,
                        "description": "Thread Node Capabilities",
                        "minValue": 0,
                        "maxValue": 31,
                    },
                    {
                        "type": "00000703-0000-1000-8000-0026BB765291",
                        "iid": 117,
                        "perms": ["pr", "ev"],
                        "format": "int",
                        "value": 127,
                        "description": "Thread Status",
                        "minValue": 0,
                        "maxValue": 127,
                    },
                    {
                        "type": "0000022B-0000-1000-8000-0026BB765291",
                        "iid": 118,
                        "perms": ["pr"],
                        "format": "bool",
                        "value": False,
                    },
                    {
                        "type": "00000704-0000-1000-8000-0026BB765291",
                        "iid": 119,
                        "perms": ["pr", "pw"],
                        "format": "data",
                        "value": None,
                    },
                ],
            },
            {
                "iid": 64000,
                "type": "7F0DEE73-4A3F-4103-98E6-A46CD301BDFB",
                "characteristics": [
                    {
                        "type": "000000A5-0000-1000-8000-0026BB765291",
                        "iid": 64001,
                        "perms": ["pr", "hd"],
                        "format": "data",
                        "value": None,
                    },
                    {
                        "type": "00000023-0000-1000-8000-0026BB765291",
                        "iid": 64002,
                        "perms": ["pr", "hd"],
                        "format": "string",
                        "value": "",
                        "description": "Name",
                        "maxLen": 64,
                    },
                    {
                        "type": "44FF6853-58DB-4956-B298-5F6650DD61F6",
                        "iid": 64003,
                        "perms": ["pw", "hd"],
                        "format": "data",
                    },
                    {
                        "type": "CF68C40F-DC6F-4F7E-918C-4C536B643A2B",
                        "iid": 64004,
                        "perms": ["pr", "pw", "hd"],
                        "format": "int",
                        "value": 3,
                        "minValue": 0,
                        "maxValue": 3,
                    },
                    {
                        "type": "4058C2B8-4545-4E77-B6B7-157C38F9718B",
                        "iid": 64005,
                        "perms": ["pr", "pw", "hd"],
                        "format": "int",
                        "value": 1,
                        "minValue": 1,
                        "maxValue": 5,
                    },
                    {
                        "type": "B498F4B5-6364-4F79-B5CC-1563ADE070DF",
                        "iid": 64006,
                        "perms": ["pr", "pw", "hd"],
                        "format": "int",
                        "value": 1,
                        "minValue": 0,
                        "maxValue": 1,
                    },
                    {
                        "type": "AFAE7AD2-8DD3-4B20-BAE0-C0B18B79EDB5",
                        "iid": 64007,
                        "perms": ["pw", "hd"],
                        "format": "data",
                    },
                    {
                        "type": "87D91EC6-C508-4CAD-89F1-A21B0BF179A0",
                        "iid": 64008,
                        "perms": ["pr", "hd"],
                        "format": "data",
                        "value": None,
                    },
                    {
                        "type": "4C3E2641-F57F-11E3-A3AC-0800200C9A66",
                        "iid": 64009,
                        "perms": ["pr", "hd"],
                        "format": "int",
                        "value": 4108458795,
                        "unit": "seconds",
                        "minValue": 0,
                        "maxValue": 4108458795,
                    },
                    {
                        "type": "EEC26990-F628-11E3-A3AC-0800200C9A66",
                        "iid": 64010,
                        "perms": ["pr", "pw", "hd"],
                        "format": "int",
                        "value": 4,
                        "minValue": 4,
                        "maxValue": 8,
                    },
                    {
                        "type": "BCDE3B9E-3963-4123-B24D-42ECCBB3A9C4",
                        "iid": 64011,
                        "perms": ["pr", "hd"],
                        "format": "data",
                        "value": None,
                    },
                    {
                        "type": "58893C80-94A2-11E7-ABC4-CEC278B6B50A",
                        "iid": 64012,
                        "perms": ["pr", "pw", "hd"],
                        "format": "data",
                        "value": None,
                    },
                    {
                        "type": "7A16E155-56F2-4701-89DF-A58403C7FDE2",
                        "iid": 64013,
                        "perms": ["pr", "hd"],
                        "format": "string",
                        "value": "",
                        "maxLen": 64,
                    },
                    {
                        "type": "5D7F230E-C4AF-465B-87B2-00988303794A",
                        "iid": 64014,
                        "perms": ["pw", "hd"],
                        "format": "int",
                        "minValue": 0,
                        "maxValue": 1,
                    },
                    {
                        "type": "1EAF8D27-EE13-4D07-9EB7-249C740CBA10",
                        "iid": 64015,
                        "perms": ["pr", "hd"],
                        "format": "int",
                        "value": 1,
                        "minValue": 0,
                        "maxValue": 1,
                    },
                    {
                        "type": "FEB28615-DEC7-46D9-BD51-7C019D0E30BA",
                        "iid": 64016,
                        "perms": ["pr", "pw", "hd"],
                        "format": "bool",
                        "value": False,
                    },
                ],
            },
            {
                "iid": 64032,
                "type": "883F45EC-14CB-46AA-9864-9A4E782B33D0",
                "characteristics": [
                    {
                        "type": "000000A5-0000-1000-8000-0026BB765291",
                        "iid": 64033,
                        "perms": ["pr", "hd"],
                        "format": "data",
                        "value": None,
                    },
                    {
                        "type": "26002998-E001-4812-8C08-5CD2AFDA0830",
                        "iid": 64034,
                        "perms": ["pr", "hd"],
                        "format": "data",
                        "value": None,
                    },
                    {
                        "type": "FF530C78-CD50-4BB9-BBD4-0712F32B3796",
                        "iid": 64035,
                        "perms": ["pr", "hd"],
                        "format": "data",
                        "value": None,
                    },
                ],
            },
            {
                "iid": 64048,
                "type": "1F6B43AA-94DE-4BA9-981C-DA38823117BD",
                "characteristics": [
                    {
                        "type": "000000A5-0000-1000-8000-0026BB765291",
                        "iid": 64049,
                        "perms": ["pr", "hd"],
                        "format": "data",
                        "value": None,
                    },
                    {
                        "type": "048D8799-695B-4A7F-A7F7-A4A1301587FE",
                        "iid": 64050,
                        "perms": ["pr", "hd"],
                        "format": "int",
                        "value": 0,
                    },
                    {
                        "type": "66B7C7FD-95A7-4F89-B0AD-38073A67C46C",
                        "iid": 64051,
                        "perms": ["pr", "hd"],
                        "format": "data",
                        "value": None,
                    },
                    {
                        "type": "507EFC3F-9231-438C-976A-FA04427F1F8F",
                        "iid": 64052,
                        "perms": ["pr", "hd"],
                        "format": "int",
                        "value": 0,
                    },
                    {
                        "type": "1DC15719-0882-4BAD-AB0F-9AEAB0600C90",
                        "iid": 64053,
                        "perms": ["pr", "hd"],
                        "format": "int",
                        "value": 0,
                    },
                ],
            },
            {
                "iid": 2560,
                "type": "00000239-0000-1000-8000-0026BB765291",
                "characteristics": [
                    {
                        "type": "000000A5-0000-1000-8000-0026BB765291",
                        "iid": 2564,
                        "perms": ["pr"],
                        "format": "data",
                        "value": None,
                    },
                    {
                        "type": "0000023A-0000-1000-8000-0026BB765291",
                        "iid": 2561,
                        "perms": ["pr"],
                        "format": "int",
                        "value": 67108863,
                        "minValue": 0,
                        "maxValue": 67108863,
                    },
                    {
                        "type": "0000023C-0000-1000-8000-0026BB765291",
                        "iid": 2562,
                        "perms": ["pr"],
                        "format": "data",
                        "value": None,
                    },
                    {
                        "type": "0000024A-0000-1000-8000-0026BB765291",
                        "iid": 2565,
                        "perms": ["pr", "ev"],
                        "format": "int",
                        "value": 0,
                    },
                ],
            },
            {
                "iid": 240,
                "type": "00000129-0000-1000-8000-0026BB765291",
                "characteristics": [
                    {
                        "type": "000000A5-0000-1000-8000-0026BB765291",
                        "iid": 241,
                        "perms": ["pr"],
                        "format": "data",
                        "value": None,
                    },
                    {
                        "type": "00000130-0000-1000-8000-0026BB765291",
                        "iid": 242,
                        "perms": ["pr"],
                        "format": "data",
                        "value": None,
                    },
                    {
                        "type": "00000131-0000-1000-8000-0026BB765291",
                        "iid": 243,
                        "perms": ["pr", "pw"],
                        "format": "data",
                        "value": None,
                    },
                    {
                        "type": "00000037-0000-1000-8000-0026BB765291",
                        "iid": 244,
                        "perms": ["pr"],
                        "format": "string",
                        "value": "",
                        "description": "Version",
                        "maxLen": 64,
                    },
                    {
                        "type": "00000138-0000-1000-8000-0026BB765291",
                        "iid": 245,
                        "perms": ["pr", "pw"],
                        "format": "data",
                        "value": None,
                    },
                    {
                        "type": "00000139-0000-1000-8000-0026BB765291",
                        "iid": 246,
                        "perms": ["pr", "ev"],
                        "format": "data",
                        "value": None,
                    },
                ],
            },
            {
                "iid": 3840,
                "type": "00000236-0000-1000-8000-0026BB765291",
                "characteristics": [
                    {
                        "type": "000000A5-0000-1000-8000-0026BB765291",
                        "iid": 3841,
                        "perms": ["pr"],
                        "format": "data",
                        "value": None,
                    },
                    {
                        "type": "00000234-0000-1000-8000-0026BB765291",
                        "iid": 3842,
                        "perms": ["pr", "ev"],
                        "format": "data",
                        "value": None,
                    },
                    {
                        "type": "00000235-0000-1000-8000-0026BB765291",
                        "iid": 3843,
                        "perms": ["pr", "ev"],
                        "format": "data",
                        "value": None,
                    },
                ],
            },
            {
                "iid": 208,
                "type": "00000237-0000-1000-8000-0026BB765291",
                "characteristics": [
                    {
                        "type": "00000238-0000-1000-8000-0026BB765291",
                        "iid": 209,
                        "perms": ["pr"],
                        "format": "data",
                        "value": None,
                    }
                ],
            },
        ],
    }
