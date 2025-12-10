#!/usr/bin/env python3
"""
Minimal round-trip tests for XOR encryption, signing/verification, and DH key exchange.
Run: python test_roundtrip.py
"""
from utils import xor_encrypt_decrypt, hash_message, create_signed_message, verify_message
from key_exchange import KeyExchange
from ecc import PrivateKey, N
from random import randint


def test_xor_roundtrip():
    plaintext = "Hello, secure world!"
    key = "supersecretkey"
    encrypted = xor_encrypt_decrypt(plaintext, key)
    decrypted = xor_encrypt_decrypt(encrypted, key).decode()
    assert decrypted == plaintext, f"XOR roundtrip failed: {decrypted}"
    print("[PASS] XOR encrypt/decrypt roundtrip")


def test_sign_verify():
    secret = randint(1, N - 1)
    pk = PrivateKey(secret)
    message = "Test message for signing"
    signed = create_signed_message(pk, message)
    assert verify_message(pk.point, signed), "Signature verification failed"
    print("[PASS] Sign and verify message")


def test_dh_shared_secret():
    alice = KeyExchange()
    bob = KeyExchange()
    alice_pub = alice.public_component()
    bob_pub = bob.public_component()
    alice_shared = alice.derive_shared(bob_pub)
    bob_shared = bob.derive_shared(alice_pub)
    assert alice_shared == bob_shared, f"DH mismatch: {alice_shared} != {bob_shared}"
    print("[PASS] DH shared secret matches on both sides")


if __name__ == "__main__":
    test_xor_roundtrip()
    test_sign_verify()
    test_dh_shared_secret()
    print("\nAll tests passed!")
