"""Generate a fresh CA, server, and client identity.

Run this once before starting the server/client for the first time::

    python -m secure_chat.pki.generate_keys

It creates:

* ``ca_private.pem``          — the Certificate Authority's private key
* ``server_private.pem`` / ``server_certificate.pem``
* ``client_private.pem`` / ``client_certificate.pem``

Each certificate is signed by the CA and bound to the matching private key, so
the identity used for signing genuinely corresponds to the certificate's public
key. These files are secrets and are excluded from version control via
``.gitignore``.
"""
from ..config import (
    CA_PRIVATE_KEY_PATH,
    CLIENT_CERT_PATH,
    CLIENT_PRIVATE_KEY_PATH,
    SERVER_CERT_PATH,
    SERVER_PRIVATE_KEY_PATH,
)
from ..crypto.ecc import N, PrivateKey
from ..crypto.rng import randint
from .certificate_authority import CertificateAuthority, PrivateKeyWrapper


def _make_identity(ca: CertificateAuthority, subject: str, key_path: str, cert_path: str) -> None:
    """Create a private key + CA-signed certificate for ``subject``."""
    private_key = PrivateKey(randint(1, N - 1))
    PrivateKeyWrapper(private_key).save(key_path)
    certificate = ca.sign_certificate(subject, private_key.point)
    certificate.save(cert_path)
    print(f"  {subject:8s} -> {key_path}, {cert_path}")


def main() -> None:
    print("Generating fresh identities...")
    ca = CertificateAuthority()
    ca.get_private_key_wrapper().save(CA_PRIVATE_KEY_PATH)
    print(f"  {'CA':8s} -> {CA_PRIVATE_KEY_PATH}")

    _make_identity(ca, "Server", SERVER_PRIVATE_KEY_PATH, SERVER_CERT_PATH)
    _make_identity(ca, "User", CLIENT_PRIVATE_KEY_PATH, CLIENT_CERT_PATH)
    print("Done. Keep the .pem files private — they are your secrets.")


if __name__ == "__main__":
    main()
