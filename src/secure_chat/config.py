"""Central runtime configuration for secure-chat.

Deployment settings (networking, DH parameters, file paths) live here and can
be overridden via environment variables, so nothing environment-specific is
hard-coded. Cryptographic protocol invariants live in ``crypto/constants.py``.
"""
import os

from .crypto.constants import FIELD_PRIME

# --- Networking -------------------------------------------------------------
HOST: str = os.getenv("SECURE_CHAT_HOST", "localhost")
PORT: int = int(os.getenv("SECURE_CHAT_PORT", "8080"))
BACKLOG: int = int(os.getenv("SECURE_CHAT_BACKLOG", "10"))

# --- Diffie-Hellman parameters ----------------------------------------------
# Reuse the secp256k1 field prime as the DH modulus so the group is a large,
# well-known prime. The generator is a simple demo value; this is educational,
# not a vetted DH group.
P_FIELD: int = FIELD_PRIME
G_GENERATOR_NUM: int = 5

# --- File paths -------------------------------------------------------------
CA_PRIVATE_KEY_PATH: str = os.getenv("SECURE_CHAT_CA_KEY", "ca_private.pem")
SERVER_CERT_PATH: str = os.getenv("SECURE_CHAT_SERVER_CERT", "server_certificate.pem")
SERVER_PRIVATE_KEY_PATH: str = os.getenv("SECURE_CHAT_SERVER_KEY", "server_private.pem")
CLIENT_CERT_PATH: str = os.getenv("SECURE_CHAT_CLIENT_CERT", "client_certificate.pem")
CLIENT_PRIVATE_KEY_PATH: str = os.getenv("SECURE_CHAT_CLIENT_KEY", "client_private.pem")
