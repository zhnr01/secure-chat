"""A from-scratch authenticated stream cipher (AEAD-style).

This module replaces the original repeating-key XOR "encryption" with a design
that is actually safe against the two attacks XOR was vulnerable to:

* **Confidentiality** — a fresh, message-length keystream is generated in
  counter mode from HMAC-SHA256, using a random 96-bit nonce per message. No
  keystream is ever reused, which is what made repeating-key XOR breakable.
* **Integrity / authenticity** — encrypt-then-MAC: an HMAC-SHA256 tag is
  computed over ``nonce || ciphertext`` and verified in constant time before
  decryption. Any tampering is detected and rejected.

Key material is split from the Diffie-Hellman shared secret using HKDF
(RFC 5869), so the encryption key and MAC key are independent.

Everything here uses only the Python standard library (``hashlib``, ``hmac``,
``os``). It is educational: correct in construction, but not constant-time in
the keystream generation and not audited. Prefer a vetted AEAD (AES-GCM,
ChaCha20-Poly1305) for real secrets.

Wire format of a sealed message (before base64/JSON transport)::

    nonce (12 bytes) || ciphertext (N bytes) || tag (32 bytes)
"""
import base64
import hashlib
import hmac
import os
from dataclasses import dataclass

_HASH = hashlib.sha256
_HASH_LEN = 32           # SHA-256 output size in bytes
NONCE_LEN = 12           # 96-bit nonce, standard AEAD nonce size
TAG_LEN = _HASH_LEN      # HMAC-SHA256 tag size

# Domain-separation labels so the two derived keys can never collide.
_INFO_ENC = b"secure-chat/v1/enc"
_INFO_MAC = b"secure-chat/v1/mac"
_SALT = b"secure-chat/v1/salt"


def hkdf(ikm: bytes, length: int, *, salt: bytes = b"", info: bytes = b"") -> bytes:
    """HKDF (RFC 5869) using HMAC-SHA256. Returns ``length`` bytes of key material.

    HKDF has two steps: *extract* condenses the input keying material into a
    fixed-size pseudorandom key, and *expand* stretches it to the desired
    length while binding it to a context (``info``).
    """
    if length > 255 * _HASH_LEN:
        raise ValueError("HKDF cannot produce more than 255*HashLen bytes")

    # Extract
    prk = hmac.new(salt or b"\x00" * _HASH_LEN, ikm, _HASH).digest()

    # Expand
    okm = b""
    block = b""
    counter = 1
    while len(okm) < length:
        block = hmac.new(prk, block + info + bytes([counter]), _HASH).digest()
        okm += block
        counter += 1
    return okm[:length]


@dataclass(frozen=True)
class SessionKeys:
    """A pair of independent keys derived from the shared secret."""

    enc_key: bytes
    mac_key: bytes

    @staticmethod
    def derive(shared_secret: int) -> "SessionKeys":
        """Derive encryption and MAC keys from a Diffie-Hellman shared secret."""
        # Represent the shared secret as fixed-width bytes for a stable IKM.
        ikm = shared_secret.to_bytes((shared_secret.bit_length() + 7) // 8 or 1, "big")
        enc = hkdf(ikm, _HASH_LEN, salt=_SALT, info=_INFO_ENC)
        mac = hkdf(ikm, _HASH_LEN, salt=_SALT, info=_INFO_MAC)
        return SessionKeys(enc_key=enc, mac_key=mac)


def _keystream(key: bytes, nonce: bytes, length: int) -> bytes:
    """Generate ``length`` bytes of keystream in HMAC-SHA256 counter mode.

    block_i = HMAC-SHA256(key, nonce || counter_i); concatenated and truncated.
    """
    out = bytearray()
    counter = 0
    while len(out) < length:
        counter_bytes = counter.to_bytes(8, "big")
        out.extend(hmac.new(key, nonce + counter_bytes, _HASH).digest())
        counter += 1
    return bytes(out[:length])


def encrypt(keys: SessionKeys, plaintext: bytes, *, nonce: bytes | None = None) -> bytes:
    """Encrypt and authenticate ``plaintext``. Returns nonce || ciphertext || tag."""
    if isinstance(plaintext, str):
        raise TypeError("plaintext must be bytes")
    if nonce is None:
        nonce = os.urandom(NONCE_LEN)
    if len(nonce) != NONCE_LEN:
        raise ValueError(f"nonce must be {NONCE_LEN} bytes")

    ks = _keystream(keys.enc_key, nonce, len(plaintext))
    ciphertext = bytes(p ^ k for p, k in zip(plaintext, ks))
    tag = hmac.new(keys.mac_key, nonce + ciphertext, _HASH).digest()
    return nonce + ciphertext + tag


class AuthenticationError(Exception):
    """Raised when a sealed message fails its integrity check."""


def decrypt(keys: SessionKeys, sealed: bytes) -> bytes:
    """Verify and decrypt a ``nonce || ciphertext || tag`` blob.

    Raises :class:`AuthenticationError` if the tag does not match — the message
    was tampered with, truncated, or encrypted under a different key.
    """
    if len(sealed) < NONCE_LEN + TAG_LEN:
        raise AuthenticationError("sealed message too short")

    nonce = sealed[:NONCE_LEN]
    tag = sealed[-TAG_LEN:]
    ciphertext = sealed[NONCE_LEN:-TAG_LEN]

    expected = hmac.new(keys.mac_key, nonce + ciphertext, _HASH).digest()
    # Constant-time comparison prevents timing attacks on the tag.
    if not hmac.compare_digest(expected, tag):
        raise AuthenticationError("message authentication failed")

    ks = _keystream(keys.enc_key, nonce, len(ciphertext))
    return bytes(c ^ k for c, k in zip(ciphertext, ks))


def seal_text(keys: SessionKeys, plaintext: str) -> str:
    """Encrypt a string and return a base64 token safe to embed in JSON."""
    sealed = encrypt(keys, plaintext.encode("utf-8"))
    return base64.b64encode(sealed).decode("ascii")


def open_text(keys: SessionKeys, token: str) -> str:
    """Reverse :func:`seal_text`. Raises AuthenticationError on tampering."""
    sealed = base64.b64decode(token.encode("ascii"))
    return decrypt(keys, sealed).decode("utf-8")
