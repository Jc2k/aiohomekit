from aiohomekit.meshcop import Meshcop


def test_parse_tlv() -> None:
    """Test the TLV parser."""
    dataset_tlv = (
        "0E080000000000010000000300000F35060004001FFFE0020811111111222222220708FDAD70BF"
        "E5AA15DD051000112233445566778899AABBCCDDEEFF030E4F70656E54687265616444656D6F01"
        "0212340410445F2B5CA6F2A93A55CE570A70EFEECB0C0402A0F7F8"
    )

    struct = Meshcop.decode(bytes.fromhex(dataset_tlv))

    assert struct.networkname == "OpenThreadDemo"
    assert struct.channel == 15
    assert struct.panid == 4660
    assert struct.extpanid == bytes.fromhex("1111111122222222")
    assert struct.pskc == bytes.fromhex("445f2b5ca6f2a93a55ce570a70efeecb")
    assert struct.networkkey == bytes.fromhex("00112233445566778899aabbccddeeff")
    assert struct.meshlocalprefix == bytes.fromhex("fdad70bfe5aa15dd")
    assert struct.securitypolicy == bytes.fromhex("02a0f7f8")
    assert struct.activetimestamp == bytes.fromhex("0000000000010000")
    assert struct.channelmask == bytes.fromhex("0004001fffe0")
