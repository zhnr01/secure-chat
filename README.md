
# 🔐 Secure Encrypted Chatroom

A Python-based chatroom application that uses **Elliptic Curve Cryptography (ECC)**, **Digital Certificates**, and **Diffie-Hellman Key Exchange** to establish **end-to-end encrypted communication** between clients via a server.

---

## 🚀 Features

- ✅ **CLI and GUI clients** (PyQt5)
- 🔐 **ECC digital signatures** (custom implementation)
- 📜 **Certificate Authority (CA)** to verify identities
- 🔑 **Diffie-Hellman key exchange** to derive session keys
- 🔁 **End-to-end encrypted messaging** (XOR for simplicity)
- 🔎 **Message authenticity verification** using ECDSA
- 🌐 **Multi-client support** via threaded server

---

## 🔧 Architecture Overview

1. **Certificates**:
   - Both client and server hold a certificate signed by the local CA (`ca_private.pem`).
   - Certificates are verified using the CA's public key before communication begins.

2. **Key Exchange**:
   - Each party generates a temporary DH key.
   - Both parties derive a **shared secret** for session encryption.

3. **Message Flow**:
   - Messages are encrypted using XOR with the shared key.
   - Each message is **signed using ECDSA** and verified by the receiver.

4. **Server Role**:
   - Verifies client certificates and messages.
   - Broadcasts messages to all connected clients (with proper re-encryption).

---

## 📁 File Structure

```
project/
├── server.py                  # Server code
├── clientcli.py               # CLI client
├── clientgui.py               # GUI client (PyQt5)
├── config.py                  # Central configuration (host, port, primes, keys)
├── utils.py                   # Shared utilities (XOR, signing, cert parsing)
├── protocol.py                # Length-prefixed JSON framing helpers
├── key_exchange.py            # KeyExchange class for Diffie-Hellman
├── messages.py                # SignedMessage dataclass
├── logging_util.py            # Logging setup utility
├── ecc.py                     # ECC math (field, curve, signatures)
├── certificate_authority.py   # CA, certificate signing, PEM handling
├── ca_private.pem             # Certificate Authority private key
├── client_certificate.pem     # Client certificate
├── server_certificate.pem     # Server certificate
├── requirements.txt           # Python dependencies
└── README.md                  # You are here
```

## 📚 Based On

Parts of the ECC code, especially the `ecc.py` file, are based on the book:  
**“Programming Bitcoin” by Jimmy Song**  
🔗 [https://github.com/jimmysong/programmingbitcoin](https://github.com/jimmysong/programmingbitcoin)

---



---

## 🛠 Requirements

- Python 3.10+
- PyQt5 (for GUI client)

Install dependencies:

```bash
pip install -r requirements.txt
```

---

## ⚙️ Configuration

All tunable parameters live in `config.py`:

| Variable | Description |
|----------|-------------|
| `HOST` | Server bind address (default `localhost`) |
| `PORT` | Server port (default `8080`) |
| `RECV_BYTES` | Socket buffer size |
| `P_FIELD` | DH prime modulus (secp256k1 field prime) |
| `G_GENERATOR_NUM` | DH generator |

---

## 🧪 How to Run

### 1. 🔑 Generate Certificates (Optional if already present)

> If not already created:
```python
from certificate_authority import CertificateAuthority, PrivateKeyWrapper

ca = CertificateAuthority()
ca.get_private_key_wrapper().save('ca_private.pem')

server_cert = ca.sign_certificate("Server", ca.public_key)
server_cert.save('server_certificate.pem')

client_cert = ca.sign_certificate("User", ca.public_key)
client_cert.save('client_certificate.pem')
```

---

### 2. ▶️ Run the Server

```bash
python server.py
# Or with CLI overrides:
python server.py --host 0.0.0.0 --port 9000
```

---

### 3. 💻 Run the CLI Client

```bash
python clientcli.py
# Or with CLI overrides:
python clientcli.py --host 192.168.1.10 --port 9000
```

---

### 4. 🖥 Run the GUI Client

```bash
python clientgui.py
```

---

## 🔐 Security Notes

* **ECC + ECDSA**: Custom implementation of signing and verification (see `ecc.py`).
* **Certificates**: Manually signed by local CA (demo-style trust).
* **Key Exchange**: Uses `KeyExchange` class wrapping Diffie-Hellman with configurable prime.
* **Protocol Framing**: Length-prefixed JSON messages via `protocol.py` prevent partial reads.
* **Encryption**: Simple XOR used for demo purposes. For real-world apps, use AES or ChaCha20.

---

## 🧪 Running Tests

A minimal round-trip test validates XOR, signing, verification, and DH:

```bash
python test_roundtrip.py
```

---

## 🎓 Educational Value

This project is built from **scratch** to help understand:

* Elliptic Curve math
* How digital signatures work
* The role of CAs and certificates
* Key exchange protocols
* Secure socket programming in Python

---

> ⚠️ This project is a **work-in-progress prototype** intended for learning and experimentation. Not ready for production.

---
