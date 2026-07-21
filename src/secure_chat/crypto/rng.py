"""Cryptographically secure random helpers.

The standard library ``random`` module is a Mersenne Twister — fast but
predictable, and never appropriate for keys. Everything here draws from
``secrets``/``os.urandom`` instead.
"""
import secrets


def randint(low: int, high: int) -> int:
    """Return a secure random integer in the inclusive range [low, high]."""
    if low > high:
        raise ValueError("low must be <= high")
    return low + secrets.randbelow(high - low + 1)
