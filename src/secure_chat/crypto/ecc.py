"""Elliptic Curve Cryptography primitives for secp256k1.

Implemented from scratch on the Python standard library. The module provides
finite-field arithmetic, curve point operations, and ECDSA signing/verification
with RFC 6979 deterministic nonces.

Based on 'Programming Bitcoin' by Jimmy Song.

This is an educational implementation: it is not constant-time and has not been
audited, so it should not be used to protect real secrets.
"""
from __future__ import annotations

import hashlib
import hmac

from .constants import (
    BYTE_ORDER,
    CURVE_A,
    CURVE_B,
    FIELD_PRIME,
    GENERATOR_X,
    GENERATOR_Y,
    GROUP_ORDER,
    SCALAR_BYTE_LENGTH,
)

# Public aliases kept for readability at call sites.
A = CURVE_A
B = CURVE_B
P = FIELD_PRIME
N = GROUP_ORDER

_SHA256 = hashlib.sha256


class FieldElement:
    """An element of the finite field GF(prime) with modular arithmetic."""

    def __init__(self, num: int, prime: int):
        if num >= prime or num < 0:
            raise ValueError(f"Num {num} not in field range 0 to {prime - 1}")
        self.num = num
        self.prime = prime

    def __repr__(self) -> str:
        return f"FieldElement_{self.prime}({self.num})"

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, FieldElement):
            return False
        return self.num == other.num and self.prime == other.prime

    def __ne__(self, other: object) -> bool:
        return not self == other

    def _assert_same_field(self, other: FieldElement) -> None:
        if self.prime != other.prime:
            raise TypeError("Cannot operate on numbers in different fields")

    def __add__(self, other: FieldElement) -> FieldElement:
        self._assert_same_field(other)
        return self.__class__((self.num + other.num) % self.prime, self.prime)

    def __sub__(self, other: FieldElement) -> FieldElement:
        self._assert_same_field(other)
        return self.__class__((self.num - other.num) % self.prime, self.prime)

    def __mul__(self, other: FieldElement) -> FieldElement:
        self._assert_same_field(other)
        return self.__class__((self.num * other.num) % self.prime, self.prime)

    def __pow__(self, exponent: int) -> FieldElement:
        n = exponent % (self.prime - 1)
        return self.__class__(pow(self.num, n, self.prime), self.prime)

    def __truediv__(self, other: FieldElement) -> FieldElement:
        self._assert_same_field(other)
        # Division by Fermat's little theorem: a^-1 == a^(p-2) (mod p).
        inverse = pow(other.num, self.prime - 2, self.prime)
        return self.__class__((self.num * inverse) % self.prime, self.prime)

    def __rmul__(self, coefficient: int) -> FieldElement:
        return self.__class__((self.num * coefficient) % self.prime, self.prime)


class Point:
    """A point on the elliptic curve y^2 = x^3 + ax + b.

    The point at infinity (the group's identity element) is represented by
    ``x`` and ``y`` both being ``None``.
    """

    def __init__(self, x, y, a, b):
        self.a = a
        self.b = b
        self.x = x
        self.y = y
        if self.x is None and self.y is None:
            return
        if self.y**2 != self.x**3 + a * x + b:
            raise ValueError(f"({x}, {y}) is not on the curve")

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, Point):
            return False
        return (
            self.x == other.x
            and self.y == other.y
            and self.a == other.a
            and self.b == other.b
        )

    def __ne__(self, other: object) -> bool:
        return not self == other

    def __repr__(self) -> str:
        if self.x is None:
            return "Point(infinity)"
        if isinstance(self.x, FieldElement):
            return f"Point({self.x.num},{self.y.num})_{self.a.num}_{self.b.num}"
        return f"Point({self.x},{self.y})_{self.a}_{self.b}"

    def _is_infinity(self) -> bool:
        return self.x is None

    def __add__(self, other: Point) -> Point:
        if self.a != other.a or self.b != other.b:
            raise TypeError(f"Points {self}, {other} are not on the same curve")

        # Adding the identity element returns the other operand unchanged.
        if self._is_infinity():
            return other
        if other._is_infinity():
            return self

        # Points on a vertical line sum to the point at infinity.
        if self.x == other.x and self.y != other.y:
            return self.__class__(None, None, self.a, self.b)

        # Distinct x-coordinates: add using the slope of the connecting line.
        if self.x != other.x:
            slope = (other.y - self.y) / (other.x - self.x)
            x = slope**2 - self.x - other.x
            y = slope * (self.x - x) - self.y
            return self.__class__(x, y, self.a, self.b)

        # Doubling a point whose y is zero yields the point at infinity.
        if self == other and self.y == 0 * self.x:
            return self.__class__(None, None, self.a, self.b)

        # Otherwise the points are equal: double using the tangent slope.
        slope = (3 * self.x**2 + self.a) / (2 * self.y)
        x = slope**2 - 2 * self.x
        y = slope * (self.x - x) - self.y
        return self.__class__(x, y, self.a, self.b)

    def __rmul__(self, coefficient: int) -> Point:
        # Double-and-add gives O(log n) scalar multiplication.
        coef = coefficient
        current = self
        result = self.__class__(None, None, self.a, self.b)
        while coef:
            if coef & 1:
                result += current
            current += current
            coef >>= 1
        return result


class S256Field(FieldElement):
    """A field element fixed to the secp256k1 field prime.

    ``prime`` is accepted only so inherited arithmetic (which reconstructs via
    ``self.__class__(num, self.prime)``) keeps working; it must equal the
    secp256k1 field prime if supplied.
    """

    def __init__(self, num: int, prime: int | None = None):
        if prime is not None and prime != P:
            raise ValueError("S256Field prime is fixed to the secp256k1 field prime")
        super().__init__(num=num, prime=P)

    def __repr__(self) -> str:
        return f"{self.num:x}".zfill(64)


class S256Point(Point):
    """A point on secp256k1, with ECDSA verification."""

    def __init__(self, x, y, a=None, b=None):
        a, b = S256Field(A), S256Field(B)
        if isinstance(x, int):
            super().__init__(x=S256Field(x), y=S256Field(y), a=a, b=b)
        else:
            super().__init__(x=x, y=y, a=a, b=b)

    def __repr__(self) -> str:
        if self.x is None:
            return "S256Point(infinity)"
        return f"S256Point({self.x}, {self.y})"

    def __rmul__(self, coefficient: int) -> S256Point:
        # Reduce the scalar modulo the group order before multiplying.
        return super().__rmul__(coefficient % N)

    def verify(self, z: int, sig: Signature) -> bool:
        """Return True if ``sig`` is a valid signature over hash ``z``."""
        s_inv = pow(sig.s, N - 2, N)
        u = z * s_inv % N
        v = sig.r * s_inv % N
        total = u * G + v * self
        return total.x.num == sig.r


G = S256Point(GENERATOR_X, GENERATOR_Y)


class Signature:
    """An ECDSA signature, expressed as the pair (r, s)."""

    def __init__(self, r: int, s: int):
        self.r = r
        self.s = s

    def __repr__(self) -> str:
        return f"Signature({self.r:x},{self.s:x})"


class PrivateKey:
    """An ECDSA private key that can sign message hashes."""

    def __init__(self, secret: int):
        self.secret = secret
        self.point = secret * G

    def hex(self) -> str:
        return f"{self.secret:x}".zfill(64)

    def sign(self, z: int) -> Signature:
        k = self.deterministic_k(z)
        r = (k * G).x.num
        k_inv = pow(k, N - 2, N)
        s = (z + r * self.secret) * k_inv % N
        # Enforce low-s (BIP-62) to remove signature malleability. Integer
        # division is required here: N // 2 on a float would lose precision.
        if s > N // 2:
            s = N - s
        return Signature(r, s)

    def deterministic_k(self, z: int) -> int:
        """Derive the ECDSA nonce deterministically per RFC 6979.

        A deterministic nonce removes the most common way homemade ECDSA leaks
        the private key: reusing or weakly generating the per-signature nonce.
        """
        k = b"\x00" * SCALAR_BYTE_LENGTH
        v = b"\x01" * SCALAR_BYTE_LENGTH
        if z > N:
            z -= N
        z_bytes = z.to_bytes(SCALAR_BYTE_LENGTH, BYTE_ORDER)
        secret_bytes = self.secret.to_bytes(SCALAR_BYTE_LENGTH, BYTE_ORDER)
        k = hmac.new(k, v + b"\x00" + secret_bytes + z_bytes, _SHA256).digest()
        v = hmac.new(k, v, _SHA256).digest()
        k = hmac.new(k, v + b"\x01" + secret_bytes + z_bytes, _SHA256).digest()
        v = hmac.new(k, v, _SHA256).digest()
        while True:
            v = hmac.new(k, v, _SHA256).digest()
            candidate = int.from_bytes(v, BYTE_ORDER)
            if 1 <= candidate < N:
                return candidate
            k = hmac.new(k, v + b"\x00", _SHA256).digest()
            v = hmac.new(k, v, _SHA256).digest()
