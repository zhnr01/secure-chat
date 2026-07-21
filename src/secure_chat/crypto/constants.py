"""Cryptographic protocol constants.

These are invariants of the algorithms themselves (curve parameters, encoding
conventions), not deployment configuration. They live here, next to the crypto
that defines them, rather than in ``config.py`` which is reserved for runtime
settings such as host and port.
"""

# secp256k1 domain parameters.
CURVE_A = 0
CURVE_B = 7
FIELD_PRIME = 2**256 - 2**32 - 977
GROUP_ORDER = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141

# secp256k1 generator point coordinates.
GENERATOR_X = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
GENERATOR_Y = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8

# A 256-bit scalar or field element serializes to 32 bytes, big-endian.
SCALAR_BYTE_LENGTH = 32
BYTE_ORDER = "big"
