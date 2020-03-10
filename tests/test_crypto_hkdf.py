from aiohomekit.crypto import hkdf_derive


def test_derive():
    material = hkdf_derive(
        b"1" * 32, "Pair-Verify-Encrypt-Salt", "Pair-Verify-Encrypt-Info"
    )

    assert material == (
        b'\x8fC1v\xe3N\x8c\xa2\x9c\x94\xaaa\xce\xf5"\x94$7/xq\xbf\x8c;M\xe9\xe2\xa5'
        b"N\xf9\xe5\x08"
    )
