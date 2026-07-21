"""Signed-message helpers.

Every message on the wire is signed with the sender's ECDSA private key and
verified with their certificate's public key, so a relay cannot forge or alter
messages without detection.
"""
from ..crypto.ecc import PrivateKey, S256Point, Signature
from ..crypto.hashing import sha256_int


def hash_message(message: str) -> int:
    """Return SHA-256 of ``message`` as an integer, suitable for ECDSA."""
    return sha256_int(message.encode())


def create_signed_message(private_key: PrivateKey, message: str | int) -> dict:
    """Return a dict containing the message and its ECDSA signature (r, s).

    The message is normalized to its string form *before* hashing so that the
    signer and verifier always hash identical bytes — otherwise signing an int
    (hashed as 32 bytes) and verifying its transported string form would never
    match.
    """
    normalized = str(message)
    z = hash_message(normalized)
    signature = private_key.sign(z)
    return {"message": normalized, "r": signature.r, "s": signature.s}


def verify_message(pub_key: S256Point, message_data: dict) -> bool:
    """Return True if the signature in ``message_data`` matches ``pub_key``."""
    z = hash_message(message_data["message"])
    sig = Signature(message_data["r"], message_data["s"])
    return pub_key.verify(z, sig)
