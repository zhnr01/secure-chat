"""Tests for the authenticated cipher and HKDF key derivation."""
import pytest

from secure_chat.crypto.cipher import (
    NONCE_LEN,
    TAG_LEN,
    AuthenticationError,
    SessionKeys,
    decrypt,
    encrypt,
    hkdf,
    open_text,
    seal_text,
)


@pytest.fixture
def keys() -> SessionKeys:
    return SessionKeys.derive(0xDEADBEEF)


def test_roundtrip_recovers_plaintext(keys):
    plaintext = b"attack at dawn"
    assert decrypt(keys, encrypt(keys, plaintext)) == plaintext


def test_text_roundtrip_preserves_unicode(keys):
    message = "hello \U0001f512 \u00e9\u00e8 end"
    assert open_text(keys, seal_text(keys, message)) == message


def test_empty_message_roundtrips(keys):
    assert decrypt(keys, encrypt(keys, b"")) == b""


def test_nonce_is_random_so_ciphertext_differs(keys):
    first = encrypt(keys, b"same input")
    second = encrypt(keys, b"same input")
    assert first != second, "reused nonce would leak that two plaintexts match"


def test_flipping_a_ciphertext_bit_is_detected(keys):
    sealed = bytearray(encrypt(keys, b"important"))
    sealed[NONCE_LEN] ^= 0x01
    with pytest.raises(AuthenticationError):
        decrypt(keys, bytes(sealed))


def test_flipping_a_tag_bit_is_detected(keys):
    sealed = bytearray(encrypt(keys, b"important"))
    sealed[-1] ^= 0x80
    with pytest.raises(AuthenticationError):
        decrypt(keys, bytes(sealed))


def test_truncated_message_is_rejected(keys):
    with pytest.raises(AuthenticationError):
        decrypt(keys, b"\x00" * (NONCE_LEN + TAG_LEN - 1))


def test_wrong_key_cannot_decrypt(keys):
    other = SessionKeys.derive(0x1234)
    sealed = encrypt(keys, b"secret")
    with pytest.raises(AuthenticationError):
        decrypt(other, sealed)


def test_derive_is_deterministic_and_splits_keys():
    a = SessionKeys.derive(42)
    b = SessionKeys.derive(42)
    assert a == b
    assert a.enc_key != a.mac_key, "encryption and MAC keys must be independent"


def test_encrypt_rejects_str_input(keys):
    with pytest.raises(TypeError):
        encrypt(keys, "must be bytes")  # type: ignore[arg-type]


def test_hkdf_matches_rfc5869_basic_case():
    # RFC 5869 Appendix A.1 test vector (SHA-256).
    ikm = bytes.fromhex("0b" * 22)
    salt = bytes.fromhex("000102030405060708090a0b0c")
    info = bytes.fromhex("f0f1f2f3f4f5f6f7f8f9")
    expected = bytes.fromhex(
        "3cb25f25faacd57a90434f64d0362f2a"
        "2d2d0a90cf1a5a4c5db02d56ecc4c5bf"
        "34007208d5b887185865"
    )
    assert hkdf(ikm, 42, salt=salt, info=info) == expected
