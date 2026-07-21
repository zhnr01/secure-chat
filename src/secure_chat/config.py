"""Central configuration for secure-chat.

Values can be overridden via environment variables so that nothing sensitive
or environment-specific is hard-coded. See ``docs/DESIGN.md`` for the rationale.
"""
import os

# --- Networking -------------------------------------------------------------
HOST: str = os.getenv("SECURE_CHAT_HOST", "localhost")
PORT: int = int(os.getenv("SECURE_CHAT_PORT", "8080"))
BACKLOG: int = int(os.getenv("SECURE_CHAT_BACKLOG", "10"))

# --- Diffie-Hellman parameters ----------------------------------------------
# secp256k1 field prime, reused here so the DH group is a large, well-known
# prime. G is a simple demo generator (educational; not a vetted group).
P_FIELD: int = 2**256 - 2**32 - 977
G_GENERATOR_NUM: int = 5

# --- File paths -------------------------------------------------------------
CA_PRIVATE_KEY_PATH: str = os.getenv("SECURE_CHAT_CA_KEY", "ca_private.pem")
SERVER_CERT_PATH: str = os.getenv("SECURE_CHAT_SERVER_CERT", "server_certificate.pem")
SERVER_PRIVATE_KEY_PATH: str = os.getenv("SECURE_CHAT_SERVER_KEY", "server_private.pem")
CLIENT_CERT_PATH: str = os.getenv("SECURE_CHAT_CLIENT_CERT", "client_certificate.pem")
CLIENT_PRIVATE_KEY_PATH: str = os.getenv("SECURE_CHAT_CLIENT_KEY", "client_private.pem")
