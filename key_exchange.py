from dataclasses import dataclass
from config import P_FIELD, G_GENERATOR_NUM
import random

@dataclass
class KeyExchange:
    p: int = P_FIELD
    g: int = G_GENERATOR_NUM
    private: int = 0

    def generate_private(self):
        self.private = random.randint(1, self.p - 1)
        return self.private

    def public_component(self) -> int:
        if not self.private:
            self.generate_private()
        return pow(self.g, self.private, self.p)

    def derive_shared(self, other_public: int) -> int:
        if not self.private:
            self.generate_private()
        return pow(other_public, self.private, self.p)
