# Architecture

This document explains how the pieces fit together and why the code is
organized the way it is. For usage, see the [README](../README.md).

## Design goals

1. **Build the crypto from scratch** using only the standard library, so each
   primitive is legible rather than hidden behind a library call.
2. **Keep the layers honest.** Dependencies point in one direction: application
   code depends on transport and PKI, which depend on crypto, which depends on
   nothing. The cryptography has no idea sockets exist.
3. **Make the security properties testable.** Every guarantee (tamper
   detection, certificate rejection, signature forgery rejection) has a test
   that would fail if the property broke.

## Layers

```
client / server      application: sockets, threads, user interaction
      │
      ├── transport   framing (protocol.py) + signed envelopes (messaging.py)
      ├── pki         certificates, the CA, and participant identities
      │
      └── crypto      ECC/ECDSA, the authenticated cipher, DH, RNG, constants
```

### crypto

The foundation. No module here imports from `pki`, `transport`, `server`, or
`client`.

- **`ecc.py`** — secp256k1 finite-field arithmetic, curve points, and ECDSA.
  Signing uses **RFC 6979 deterministic nonces**, which removes the most common
  way homemade ECDSA leaks the private key (a reused or weak per-signature
  nonce). Signatures are normalized to **low-s** (BIP-62) to remove
  malleability.
- **`cipher.py`** — the authenticated cipher (details below) and HKDF.
- **`key_exchange.py`** — one Diffie-Hellman participant.
- **`constants.py`** — curve parameters and encoding conventions, defined once.
- **`hashing.py`** — the shared "SHA-256 as an integer" helper used by signing.
- **`rng.py`** — wraps `secrets`/`os.urandom`; never the predictable `random`.

### pki

- **`certificate_authority.py`** — a certificate binds a subject name to a
  public key; the CA signs that binding with ECDSA. Anyone with the CA public
  key can verify a certificate offline. Also handles PEM encoding.
- **`identity.py`** — bundles the three things each participant needs (its
  signing key, its certificate, and the CA public key) and loads them from PEM.
- **`generate_keys.py`** — a one-time script that mints a CA and issues server
  and client identities.

### transport

- **`protocol.py`** — TCP is a byte stream with no message boundaries, so every
  payload is prefixed with a 4-byte big-endian length. The reader always
  consumes exactly one message, and rejects absurd frame sizes to avoid a
  memory-exhaustion DoS.
- **`messaging.py`** — wraps a payload with its ECDSA signature so the receiver
  can verify authenticity.

### server / client

The application layer composes everything above. The server is a threaded relay
(`app.py`) with per-client bookkeeping in `session.py`; the client
(`cli.py`) is an interactive REPL. Neither contains any cryptographic logic of
its own — they orchestrate the lower layers.

## The handshake

When a client connects, both sides authenticate and derive a shared session key
before any chat traffic flows:

```
Client                                   Server
  │                                         │
  │  ◀──────── server certificate ──────────│   1. Server presents its cert
  │  (verify against CA public key)          │
  │                                         │
  │────────── client certificate ─────────▶ │   2. Client presents its cert
  │                        (verify against CA)│
  │                                         │
  │  ◀──── signed DH public component ───────│   3. Server's DH share (signed)
  │────── signed DH public component ──────▶ │   4. Client's DH share (signed)
  │                                         │
  │        both derive shared secret         │   5. HKDF → session keys
  │  ═══════ encrypted, signed chat ════════ │
```

Each DH public component is signed with the sender's ECDSA key and verified
against the certificate exchanged in steps 1–2. That binds the key exchange to
the authenticated identities, so a man-in-the-middle can't substitute their own
DH share.

## The authenticated cipher

The original prototype used repeating-key XOR, which is broken two ways: a
reused keystream leaks plaintext relationships, and it offers no integrity at
all. The replacement in `cipher.py` addresses both:

- **Key separation.** The DH shared secret is run through **HKDF (RFC 5869)** to
  derive two independent keys — one for encryption, one for the MAC — with
  domain-separation labels so they can never collide.
- **Confidentiality.** A fresh keystream is generated per message in
  **HMAC-SHA256 counter mode** with a random 96-bit nonce, so no keystream is
  ever reused.
- **Integrity and authenticity.** **Encrypt-then-MAC**: an HMAC-SHA256 tag is
  computed over `nonce || ciphertext` and checked with a **constant-time
  comparison** before decryption. Any tampering, truncation, or wrong key is
  rejected with an `AuthenticationError`.

Wire format of a sealed message (before base64/JSON transport):

```
nonce (12 bytes) || ciphertext (N bytes) || tag (32 bytes)
```

## Threat model and limitations

**What it defends against:** a passive eavesdropper (traffic is encrypted), an
active tamperer (MAC + signatures), and a malicious or buggy relay (messages are
end-to-end signed, so forgery/alteration is detected).

**What it does not do — this is educational software:**

- The primitives are **not constant-time**; they can leak secrets through timing
  side channels.
- The code is **not audited**.
- The DH group uses a simple demo generator, not a vetted group.
- There is no forward secrecy across sessions, no replay protection, and no
  certificate revocation.

For real systems, use a vetted library and a standard AEAD (AES-GCM or
ChaCha20-Poly1305) over TLS.
