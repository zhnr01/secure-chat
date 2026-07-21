"""Hashing helpers shared across the crypto and PKI layers.

Centralizes the "SHA-256 then interpret as an integer" pattern that ECDSA
signing and certificate verification both rely on, so the digest size and byte
order are defined in exactly one place.
"""
import hashlib

from .constants import BYTE_ORDER


def sha256_int(data: bytes) -> int:
    """Return the SHA-256 digest of ``data`` as a big-endian integer."""
    return int.from_bytes(hashlib.sha256(data).digest(), BYTE_ORDER)
