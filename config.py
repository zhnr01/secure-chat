"""
Central configuration for secure-chat.
Avoids hardcoded literals spread across files.
"""

# Networking
HOST = "localhost"
PORT = 8080
BACKLOG = 10
RECV_BYTES = 5000

# Security parameters
# Use secp256k1 field prime for DH demo to keep consistency (educational)
P_FIELD = 2**256 - 2**32 - 977
G_GENERATOR_NUM = 5  # simple demo generator for DH pow(G, priv, P)

# Key material (demo only; do NOT use in production)
SERVER_PRIVATE_KEY_INT = 15868289705152457917503632020531026166612756857419825123766511006865265396897
CLIENT_PRIVATE_KEY_INT = 9957016483416681782736782534500483090238740989288695810619470189709094021823

# Encoding
XOR_ENCODING = "ignore"  # errors handling during decode
