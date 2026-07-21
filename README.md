# Secure Chat

An end-to-end authenticated chat built on a **from-scratch** implementation of
elliptic curve cryptography — secp256k1, ECDSA, a mini certificate authority,
Diffie-Hellman key agreement, and an authenticated cipher — using **only the
Python standard library**.

The point of the project is educational: to show how the pieces of a real
secure channel fit together by building each one by hand rather than importing
a crypto library.

> ⚠️ **Not for production.** The primitives are correct in construction but are
> not constant-time and have not been audited. Use a vetted library (e.g.
> `cryptography`, AES-GCM, ChaCha20-Poly1305) for anything real.

## What it does

- Verifies both ends with **CA-signed certificates** before any traffic flows.
- Establishes a per-session key with **Diffie-Hellman**, signed at each step so
  the exchange itself can't be tampered with.
- Encrypts every message with an **authenticated cipher** (HKDF-derived keys,
  per-message nonce, encrypt-then-MAC) — tampering is detected and rejected.
- Signs every message with **ECDSA**, so a malicious relay can't forge or alter
  messages without the recipient noticing.
- Relays between multiple clients over a **threaded TCP server**.

## Architecture

The package is layered so dependencies only point inward — the cryptography
knows nothing about sockets, and the application layer composes everything else.

```
src/secure_chat/
├── crypto/        # Pure primitives: ECC/ECDSA, HKDF+HMAC cipher, DH, secure RNG
│   ├── ecc.py             secp256k1 field, curve, and ECDSA (RFC 6979)
│   ├── cipher.py          authenticated cipher + HKDF key derivation
│   ├── key_exchange.py    Diffie-Hellman participant
│   ├── hashing.py         shared SHA-256 helper
│   ├── constants.py       curve parameters and encoding conventions
│   └── rng.py             cryptographically secure randomness
├── pki/           # Depends only on crypto
│   ├── certificate_authority.py   CA, certificates, PEM handling
│   ├── identity.py                loads a participant's (key, cert, CA key)
│   └── generate_keys.py           one-time key/cert generation script
├── transport/     # Depends only on crypto
│   ├── protocol.py        length-prefixed JSON framing
│   └── messaging.py       signed-message envelopes
├── server/        # Application layer
│   ├── app.py             threaded relay
│   └── session.py         ClientSession + thread-safe registry
├── client/
│   └── cli.py             interactive CLI client
└── config.py      # Runtime/deployment configuration
```

See [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) for the handshake sequence
and the reasoning behind each layer.

## Getting started

Requires Python 3.10+. There are no runtime dependencies.

```bash
# Install the package (editable) with dev tooling
pip install -e ".[dev]"

# 1. Generate a CA, server, and client identity (writes .pem files, git-ignored)
python -m secure_chat.pki.generate_keys

# 2. Start the server
secure-chat-server
#   or: python -m secure_chat.server.app --host 0.0.0.0 --port 9000

# 3. Start one or more clients (in separate terminals)
secure-chat-client
#   or: python -m secure_chat.client.cli --host 127.0.0.1 --port 9000
```

Type a message and press enter to send; type `exit` to leave.

## Configuration

Runtime settings live in `secure_chat/config.py` and can be overridden with
environment variables — nothing environment-specific is hard-coded.

| Variable | Environment override | Default |
|----------|----------------------|---------|
| Host | `SECURE_CHAT_HOST` | `localhost` |
| Port | `SECURE_CHAT_PORT` | `8080` |
| Listen backlog | `SECURE_CHAT_BACKLOG` | `10` |
| CA key path | `SECURE_CHAT_CA_KEY` | `ca_private.pem` |
| Server key / cert | `SECURE_CHAT_SERVER_KEY` / `SECURE_CHAT_SERVER_CERT` | `server_private.pem` / `server_certificate.pem` |
| Client key / cert | `SECURE_CHAT_CLIENT_KEY` / `SECURE_CHAT_CLIENT_CERT` | `client_private.pem` / `client_certificate.pem` |

Cryptographic invariants (curve parameters, encoding) live separately in
`crypto/constants.py`, since they are properties of the algorithms rather than
deployment settings.

## Testing

```bash
pytest          # run the suite
ruff check .    # lint
```

The suite covers the cipher (roundtrip, nonce uniqueness, tamper detection, key
separation, an RFC 5869 HKDF vector), ECDSA (sign/verify, low-s, deterministic
nonce, forgery rejection), the PKI (certificate verify/reject, PEM roundtrips),
transport framing, Diffie-Hellman agreement, and a full server-relay
integration test. CI runs these on Python 3.10–3.12.

## Credits

The elliptic curve math in `crypto/ecc.py` is based on *Programming Bitcoin* by
Jimmy Song — <https://github.com/jimmysong/programmingbitcoin>.

## License

MIT.
