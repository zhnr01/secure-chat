"""Diffie-Hellman key exchange over a large prime field.

Both parties independently generate a private exponent, exchange public
components, and derive the same shared secret without ever transmitting it.
"""
import secrets
from dataclasses import dataclass

from ..config import G_GENERATOR_NUM, P_FIELD


@dataclass
class KeyExchange:
    """A single Diffie-Hellman participant.

    ``p`` is the prime modulus, ``g`` the generator, and ``private`` the secret
    exponent (generated lazily the first time it is needed).
    """

    p: int = P_FIELD
    g: int = G_GENERATOR_NUM
    private: int = 0

    def generate_private(self) -> int:
        # secrets is a cryptographically secure RNG (unlike random).
        self.private = secrets.randbelow(self.p - 2) + 1
        return self.private

    def public_component(self) -> int:
        """Return g^private mod p — safe to send over the wire."""
        if not self.private:
            self.generate_private()
        return pow(self.g, self.private, self.p)

    def derive_shared(self, other_public: int) -> int:
        """Return other_public^private mod p — the shared secret."""
        if not self.private:
            self.generate_private()
        return pow(other_public, self.private, self.p)
