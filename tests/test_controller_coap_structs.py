from aiohomekit.controller.coap.structs import Pdu09Database


def test_decode_eve_energy():
    db = Pdu09Database.decode(
        bytes.fromhex(
            (
                "18ff19ff1a02010016ff15ff0702010006013e100014fe1314050202000401140a0220000c070100002701000000001314050203000401200a021000"
                "0c071900002701000000001314050204000401210a0210000c071900002701000000001314050205000401230a0210000c0719000027010000000013"
                "14050206000401300a0210000c071900002701000000001314050207000401520a0210000c071900002701000000001314050208000401530a021000"
                "0c0719000027010000000013230502090004103b94f9856afdc3ba40437fac1188ab340a0250000c07190000270100000000131505020a0004022002"
                "0a0210000c071b0000270100000000131418ff050219ff0b000401a60a16ff0290150a030c07080000270100000000153d07020c000601a20f020400"
                "1000142e131405020d000401a50a0210000c071b0000270100000000131405020e000401370a0210000c07190000270100000000156907020f000601"
                "551000145e13140502100004014c0a0203000c071b000027010000000013140502110004014e0a0203000c071b000027010000000013140502120004"
                "014f0a0201000c070400002701000000001314050213000401500a0230000c071b000027010000000015ab07021400060201071000149f131b050215"
                "00040202070a0210000c07060000270100000d0400001f000000131b05021600040218ff03070a0219ff90030c070600002716ff0100000d0400007f"
                "000000131505021700040204070a0230000c071b0000270100000000131505021800040206070a0210000c0719000027010000000013140502190004"
                "01a50a0210000c071b0000270100000000131505021a0004022b020a0210000c0701000027010000000015ff07021b000610529fa205269c278fff48"
                "9e0707f063e80f020200100014ff131405021c000401a50a0250000c071b0000270100000000132305021d000410529fa205269c278fff489e0731f1"
                "63e80a0250000c071b0000270100000000132305021e000410529fa205269c278fff489e071df163e80a0260000c071b00002718ff01000000001319"
                "ff2305021f000410529fa216ff05269c278fff489e0758f163e80a0270000c071b00002701000000001323050220000410529fa205269c278fff489e"
                "0716f163e80a0250000c071b00002701000000001323050221000410529fa205269c278fff489e0717f163e80a0250000c071b000027010000000013"
                "2305022200156f0410529fa205269c278fff489e071cf163e80a0260000c071b0000270100144f0000001323050223000410529fa205269c278fff48"
                "9e0721f163e80a0260000c071b00002701000000001323050224000410529fa205269c278fff489e071ef163e80a0270000c071b0000270100000000"
                "157707022500060218ff39021000146b131419ff050226000401a50a0210000c16ff071b0000270100000000131f0502270004023a020a0210000c07"
                "080000270100000d080a000000ffffff03000013150502280004023c020a0211000c071b000027010000000013150502290004024a020a0290030c07"
                "08000027010000000015ff07022a0006014a0f020100100014ff131a05022b000401230a0210000b044e616d650c0719000027010000000013270502"
                "2c000401a50a0210000b1153657276696365205369676e61747572650c071b0000270100000000133705022d0004010f0a0290030b1d43757272656e"
                "745f68656174696e675f636f6f6c696e675f73746174650c0718ff040000270100000d020019ff010000133605022e000401330a0216ffb0030b1c54"
                "61726765745f68656174696e675f636f6f6c696e675f73746174650c07040000270100000d0200010000133905022f000401110a0290030b13437572"
                "72656e745f74656d70657261747572650c0714002f270100000d08000000000015ff0020420e040000003f00001338050214ff30000401350a02b003"
                "0b125461726765745f74656d70657261747572650c0714002f270100000d08000020410000f0410e040000003f00001333050231000401360a02b003"
                "0b1954656d70657261747572655f646973706c61795f756e6974730c07040000270100000d020001000018ff1323050232000410529fa20519ff269c"
                "278fff489e072cf163e80a02600016ff0c071b00002701000000001327050233000410529fa205269c278fff489e072ef163e80a0250000c070400ad"
                "270100000d02006400001323050234000410529fa205269c278fff489e072ff163e80a0250000c071b00002701000000001326050235001524040177"
                "0a0290030b0c5374617475735f66141161756c740c07040000270100000d020001000015ad07023600060196100014a21327050237000401a50a0210"
                "000b1153657276696365205369676e61747572650c071b00002701000000001327050238000401680a0290030b0d426174746572795f6c6576656c18"
                "5f0c070400ad270100000d02006400194f00132c050239000401790a0290030b125374163b617475735f6c6f775f626174746572790c070400002701"
                "00000d0200010000131a05023a000401230a0210000b044e616d650c0719000027010000"
            )
        )
    )

    print(db)
    print(db.to_dict())

    assert db.to_dict() == [
        {
            "aid": 1,
            "services": [
                {
                    "type": "3E",
                    "iid": 1,
                    "characteristics": [
                        {"type": "14", "iid": 2, "perms": ["pw"], "format": "bool"},
                        {"type": "20", "iid": 3, "perms": ["pr"], "format": "string"},
                        {"type": "21", "iid": 4, "perms": ["pr"], "format": "string"},
                        {"type": "23", "iid": 5, "perms": ["pr"], "format": "string"},
                        {"type": "30", "iid": 6, "perms": ["pr"], "format": "string"},
                        {"type": "52", "iid": 7, "perms": ["pr"], "format": "string"},
                        {"type": "53", "iid": 8, "perms": ["pr"], "format": "string"},
                        {
                            "type": "34AB8811AC7F4340BAC3FD6A85F9943B",
                            "iid": 9,
                            "perms": ["pr", "hd"],
                            "format": "string",
                        },
                        {"type": "220", "iid": 10, "perms": ["pr"], "format": "data"},
                        {
                            "type": "A6",
                            "iid": 11,
                            "perms": ["pr", "ev"],
                            "format": "int",
                        },
                    ],
                },
                {
                    "type": "A2",
                    "iid": 12,
                    "characteristics": [
                        {"type": "A5", "iid": 13, "perms": ["pr"], "format": "data"},
                        {"type": "37", "iid": 14, "perms": ["pr"], "format": "string"},
                    ],
                },
                {
                    "type": "55",
                    "iid": 15,
                    "characteristics": [
                        {"type": "4C", "iid": 16, "perms": [], "format": "data"},
                        {"type": "4E", "iid": 17, "perms": [], "format": "data"},
                        {"type": "4F", "iid": 18, "perms": [], "format": "int"},
                        {
                            "type": "50",
                            "iid": 19,
                            "perms": ["pr", "pw"],
                            "format": "data",
                        },
                    ],
                },
                {
                    "type": "701",
                    "iid": 20,
                    "characteristics": [
                        {
                            "type": "702",
                            "iid": 21,
                            "perms": ["pr"],
                            "format": "int",
                            "minValue": 0,
                            "maxValue": 31,
                        },
                        {
                            "type": "703",
                            "iid": 22,
                            "perms": ["pr", "ev"],
                            "format": "int",
                            "minValue": 0,
                            "maxValue": 127,
                        },
                        {
                            "type": "704",
                            "iid": 23,
                            "perms": ["pr", "pw"],
                            "format": "data",
                        },
                        {"type": "706", "iid": 24, "perms": ["pr"], "format": "string"},
                        {"type": "A5", "iid": 25, "perms": ["pr"], "format": "data"},
                        {"type": "22B", "iid": 26, "perms": ["pr"], "format": "bool"},
                    ],
                },
                {
                    "type": "E863F007079E48FF8F279C2605A29F52",
                    "iid": 27,
                    "characteristics": [
                        {
                            "type": "A5",
                            "iid": 28,
                            "perms": ["pr", "hd"],
                            "format": "data",
                        },
                        {
                            "type": "E863F131079E48FF8F279C2605A29F52",
                            "iid": 29,
                            "perms": ["pr", "hd"],
                            "format": "data",
                        },
                        {
                            "type": "E863F11D079E48FF8F279C2605A29F52",
                            "iid": 30,
                            "perms": ["pw", "hd"],
                            "format": "data",
                        },
                        {
                            "type": "E863F158079E48FF8F279C2605A29F52",
                            "iid": 31,
                            "perms": ["pr", "pw", "hd"],
                            "format": "data",
                        },
                        {
                            "type": "E863F116079E48FF8F279C2605A29F52",
                            "iid": 32,
                            "perms": ["pr", "hd"],
                            "format": "data",
                        },
                        {
                            "type": "E863F117079E48FF8F279C2605A29F52",
                            "iid": 33,
                            "perms": ["pr", "hd"],
                            "format": "data",
                        },
                        {
                            "type": "E863F11C079E48FF8F279C2605A29F52",
                            "iid": 34,
                            "perms": ["pw", "hd"],
                            "format": "data",
                        },
                        {
                            "type": "E863F121079E48FF8F279C2605A29F52",
                            "iid": 35,
                            "perms": ["pw", "hd"],
                            "format": "data",
                        },
                        {
                            "type": "E863F11E079E48FF8F279C2605A29F52",
                            "iid": 36,
                            "perms": ["pr", "pw", "hd"],
                            "format": "data",
                        },
                    ],
                },
                {
                    "type": "239",
                    "iid": 37,
                    "characteristics": [
                        {"type": "A5", "iid": 38, "perms": ["pr"], "format": "data"},
                        {
                            "type": "23A",
                            "iid": 39,
                            "perms": ["pr"],
                            "format": "int",
                            "minValue": 10,
                            "maxValue": 67108863,
                        },
                        {"type": "23C", "iid": 40, "perms": ["pr"], "format": "data"},
                        {
                            "type": "24A",
                            "iid": 41,
                            "perms": ["pr", "ev"],
                            "format": "int",
                        },
                    ],
                },
                {
                    "type": "4A",
                    "iid": 42,
                    "characteristics": [
                        {"type": "23", "iid": 43, "perms": ["pr"], "format": "string"},
                        {"type": "A5", "iid": 44, "perms": ["pr"], "format": "data"},
                        {
                            "type": "F",
                            "iid": 45,
                            "perms": ["pr", "ev"],
                            "format": "int",
                            "minValue": 0,
                            "maxValue": 1,
                        },
                        {
                            "type": "33",
                            "iid": 46,
                            "perms": ["pr", "pw", "ev"],
                            "format": "int",
                            "minValue": 0,
                            "maxValue": 1,
                        },
                        {
                            "type": "11",
                            "iid": 47,
                            "perms": ["pr", "ev"],
                            "format": "float",
                            "unit": "celsius",
                            "minStep": 0.5,
                            "minValue": 0.0,
                            "maxValue": 40.0,
                        },
                        {
                            "type": "35",
                            "iid": 48,
                            "perms": ["pr", "pw", "ev"],
                            "format": "float",
                            "unit": "celsius",
                            "minStep": 0.5,
                            "minValue": 10.0,
                            "maxValue": 30.0,
                        },
                        {
                            "type": "36",
                            "iid": 49,
                            "perms": ["pr", "pw", "ev"],
                            "format": "int",
                            "minValue": 0,
                            "maxValue": 1,
                        },
                        {
                            "type": "E863F12C079E48FF8F279C2605A29F52",
                            "iid": 50,
                            "perms": ["pw", "hd"],
                            "format": "data",
                        },
                        {
                            "type": "E863F12E079E48FF8F279C2605A29F52",
                            "iid": 51,
                            "perms": ["pr", "hd"],
                            "format": "int",
                            "unit": "percentage",
                            "minValue": 0,
                            "maxValue": 100,
                        },
                        {
                            "type": "E863F12F079E48FF8F279C2605A29F52",
                            "iid": 52,
                            "perms": ["pr", "hd"],
                            "format": "data",
                        },
                        {
                            "type": "77",
                            "iid": 53,
                            "perms": ["pr", "ev"],
                            "format": "int",
                            "minValue": 0,
                            "maxValue": 1,
                        },
                    ],
                },
                {
                    "type": "96",
                    "iid": 54,
                    "characteristics": [
                        {"type": "A5", "iid": 55, "perms": ["pr"], "format": "data"},
                        {
                            "type": "68",
                            "iid": 56,
                            "perms": ["pr", "ev"],
                            "format": "int",
                            "unit": "percentage",
                            "minValue": 0,
                            "maxValue": 100,
                        },
                        {
                            "type": "79",
                            "iid": 57,
                            "perms": ["pr", "ev"],
                            "format": "int",
                            "minValue": 0,
                            "maxValue": 1,
                        },
                        {"type": "23", "iid": 58, "perms": ["pr"], "format": "string"},
                    ],
                },
            ],
        }
    ]
