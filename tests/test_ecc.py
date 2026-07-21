"""Tests for the secp256k1 field, curve, and ECDSA implementation."""
import pytest

from secure_chat.crypto.constants import GROUP_ORDER
from secure_chat.crypto.ecc import FieldElement, G, N, PrivateKey, S256Field, Signature
from secure_chat.crypto.rng import randint


def _random_key() -> PrivateKey:
    return PrivateKey(randint(1, N - 1))


def test_generator_is_on_the_curve():
    # Constructing G would raise if it were not a valid curve point.
    assert G.x is not None and G.y is not None


def test_generator_has_group_order():
    # N * G is the identity (point at infinity).
    identity = N * G
    assert identity.x is None


def test_sign_and_verify_roundtrip():
    key = _random_key()
    z = randint(1, N - 1)
    signature = key.sign(z)
    assert key.point.verify(z, signature)


def test_signature_is_low_s():
    key = _random_key()
    for _ in range(20):
        z = randint(1, N - 1)
        assert key.sign(z).s <= N // 2


def test_deterministic_k_gives_identical_signatures():
    key = _random_key()
    z = randint(1, N - 1)
    first, second = key.sign(z), key.sign(z)
    assert (first.r, first.s) == (second.r, second.s)


def test_verify_rejects_wrong_message():
    key = _random_key()
    signature = key.sign(12345)
    assert not key.point.verify(54321, signature)


def test_verify_rejects_other_signers_key():
    signer, impostor = _random_key(), _random_key()
    z = randint(1, N - 1)
    assert not impostor.point.verify(z, signer.sign(z))


def test_verify_rejects_tampered_signature():
    key = _random_key()
    z = randint(1, N - 1)
    sig = key.sign(z)
    assert not key.point.verify(z, Signature(sig.r, sig.s ^ 1))


def test_field_element_rejects_out_of_range():
    with pytest.raises(ValueError):
        FieldElement(5, 5)


def test_s256field_rejects_foreign_prime():
    with pytest.raises(ValueError):
        S256Field(1, prime=97)


def test_field_operations_are_modular():
    a = FieldElement(7, 13)
    b = FieldElement(12, 13)
    assert (a + b).num == 6  # 19 mod 13
    assert (a * b).num == (7 * 12) % 13


def test_constants_are_consistent():
    assert N == GROUP_ORDER
