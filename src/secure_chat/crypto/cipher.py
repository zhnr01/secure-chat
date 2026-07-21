"""Symmetric message cipher.

.. note::
   Stage 1 keeps the original XOR routine unchanged so the restructure is a
   pure move. Stage 2 replaces this module with a from-scratch authenticated
   stream cipher (HMAC-SHA256 keystream + encrypt-then-MAC).
"""
from typing import Union


def xor_encrypt_decrypt(data: Union[str, bytes], key: Union[str, bytes]) -> bytes:
    """XOR ``data`` against a repeating ``key`` (symmetric: encrypt == decrypt)."""
    if isinstance(data, str):
        data = data.encode()
    if isinstance(key, str):
        key = key.encode()
    key_length = len(key)
    return bytes([data[i] ^ key[i % key_length] for i in range(len(data))])
