"""Tests for Diffie-Hellman key agreement."""
from secure_chat.crypto.key_exchange import KeyExchange


def test_both_parties_derive_the_same_secret():
    alice = KeyExchange()
    bob = KeyExchange()
    alice_shared = alice.derive_shared(bob.public_component())
    bob_shared = bob.derive_shared(alice.public_component())
    assert alice_shared == bob_shared


def test_independent_exchanges_produce_different_secrets():
    alice, bob = KeyExchange(), KeyExchange()
    carol, dave = KeyExchange(), KeyExchange()
    first = alice.derive_shared(bob.public_component())
    second = carol.derive_shared(dave.public_component())
    assert first != second


def test_public_component_generates_a_private_exponent():
    party = KeyExchange()
    assert party.private == 0
    party.public_component()
    assert party.private != 0
