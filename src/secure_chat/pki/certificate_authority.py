"""Certificate Authority, certificates, and PEM handling.

A certificate binds a human-readable subject name to an ECC public key. The CA
signs that binding with its own private key; anyone holding the CA public key
can then verify a certificate without contacting the CA.
"""
import base64
import json
from enum import Enum

from ..crypto.constants import BYTE_ORDER, GROUP_ORDER, SCALAR_BYTE_LENGTH
from ..crypto.ecc import PrivateKey, Signature, S256Point
from ..crypto.hashing import sha256_int
from ..crypto.rng import randint

_HEX_RADIX = 16
_PEM_LINE_WIDTH = 64



class PEMLabel(Enum):
    """PEM block labels."""

    PRIVATE_KEY = "PRIVATE KEY"
    CERTIFICATE = "CERTIFICATE"


class PEMFormatter:
    """Encode/decode data to/from PEM (base64 wrapped in BEGIN/END markers)."""

    @staticmethod
    def encode(data: bytes, label: PEMLabel) -> str:
        base64_encoded = base64.b64encode(data).decode()
        lines = [
            base64_encoded[i:i + _PEM_LINE_WIDTH]
            for i in range(0, len(base64_encoded), _PEM_LINE_WIDTH)
        ]
        return (
            f"-----BEGIN {label.value}-----\n"
            + "\n".join(lines)
            + f"\n-----END {label.value}-----\n"
        )

    @staticmethod
    def decode(pem_data: str, label: PEMLabel) -> bytes:
        clean_data = (
            pem_data.strip()
            .replace(f"-----BEGIN {label.value}-----", "")
            .replace(f"-----END {label.value}-----", "")
            .replace("\n", "")
        )
        return base64.b64decode(clean_data)


class PEMHandler:
    """Load/save PEM files."""

    @staticmethod
    def load(filename: str, label: PEMLabel) -> bytes:
        with open(filename, "r") as f:
            pem_data = f.read()
        return PEMFormatter.decode(pem_data, label)

    @staticmethod
    def save(data: bytes, filename: str, label: PEMLabel):
        pem = PEMFormatter.encode(data, label)
        with open(filename, "w") as f:
            f.write(pem)


class PrivateKeyWrapper:
    """Wrapper to load/save private keys in PEM format."""

    def __init__(self, private_key: PrivateKey):
        self.private_key = private_key

    @property
    def point(self) -> S256Point:
        return self.private_key.point

    def save(self, filename: str):
        private_key_bytes = self.private_key.secret.to_bytes(SCALAR_BYTE_LENGTH, BYTE_ORDER)
        PEMHandler.save(private_key_bytes, filename, PEMLabel.PRIVATE_KEY)

    @staticmethod
    def load(filename: str) -> "PrivateKeyWrapper":
        raw = PEMHandler.load(filename, PEMLabel.PRIVATE_KEY)
        secret = int.from_bytes(raw, BYTE_ORDER)
        return PrivateKeyWrapper(PrivateKey(secret))


class Certificate:
    """Digital certificate: a signed binding of a subject name to a public key."""

    def __init__(self, cert_data: dict, signature: Signature):
        self.cert_data = cert_data
        self.signature = signature

    def cert_bytes(self) -> bytes:
        cert_json = {
            "cert_data": self.cert_data,
            "signature": {"r": hex(self.signature.r), "s": hex(self.signature.s)},
        }
        return json.dumps(cert_json, sort_keys=True).encode()

    def to_dict(self) -> dict:
        return json.loads(self.cert_bytes().decode())

    def save(self, filename: str):
        PEMHandler.save(self.cert_bytes(), filename, PEMLabel.CERTIFICATE)

    @staticmethod
    def _canonical_hash(cert_data: dict) -> int:
        """Hash the certificate body using its canonical (sorted) JSON form.

        Signing and verifying must hash byte-for-byte identical input, so the
        key order is fixed with ``sort_keys``.
        """
        canonical = json.dumps(cert_data, sort_keys=True).encode()
        return sha256_int(canonical)

    @staticmethod
    def from_dict(cert_dict: dict) -> "Certificate":
        return Certificate(
            cert_dict["cert_data"],
            Signature(
                r=int(cert_dict["signature"]["r"], _HEX_RADIX),
                s=int(cert_dict["signature"]["s"], _HEX_RADIX),
            ),
        )

    @staticmethod
    def load(filename: str) -> "Certificate":
        cert_dict = json.loads(PEMHandler.load(filename, PEMLabel.CERTIFICATE).decode())
        return Certificate.from_dict(cert_dict)

    def public_key(self) -> S256Point:
        """Extract the subject's public key as an S256Point."""
        return S256Point(
            int(self.cert_data["public_key_x"], _HEX_RADIX),
            int(self.cert_data["public_key_y"], _HEX_RADIX),
        )

    def verify(self, ca_public_key: S256Point) -> bool:
        """Return True if this certificate was signed by ``ca_public_key``."""
        return ca_public_key.verify(self._canonical_hash(self.cert_data), self.signature)


class CertificateAuthority:
    """Issues and signs certificates."""

    def __init__(self, private_key: PrivateKey | None = None):
        self.private_key = private_key or PrivateKey(randint(1, GROUP_ORDER - 1))
        self.public_key = self.private_key.point

    def sign_certificate(self, subject_name: str, subject_public_key: S256Point) -> Certificate:
        cert_data = {
            "subject": subject_name,
            "public_key_x": hex(subject_public_key.x.num),
            "public_key_y": hex(subject_public_key.y.num),
        }
        signature = self.private_key.sign(Certificate._canonical_hash(cert_data))
        return Certificate(cert_data, signature)

    def get_private_key_wrapper(self) -> PrivateKeyWrapper:
        return PrivateKeyWrapper(self.private_key)
