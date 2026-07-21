"""A participant's cryptographic identity.

Both the server and the client need the same three things to take part in the
protocol: their own signing key, their CA-signed certificate, and the CA's
public key to verify the peer. ``Identity`` bundles them and loads them from
PEM files in one place.
"""
from dataclasses import dataclass

from ..crypto.ecc import PrivateKey, S256Point
from .certificate_authority import Certificate, PrivateKeyWrapper


@dataclass(frozen=True)
class Identity:
    """The key material one participant presents and verifies against."""

    signing_key: PrivateKey
    certificate: Certificate
    ca_public_key: S256Point

    @staticmethod
    def load(private_key_path: str, certificate_path: str, ca_key_path: str) -> "Identity":
        return Identity(
            signing_key=PrivateKeyWrapper.load(private_key_path).private_key,
            certificate=Certificate.load(certificate_path),
            ca_public_key=PrivateKeyWrapper.load(ca_key_path).point,
        )
