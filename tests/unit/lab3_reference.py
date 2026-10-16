"""Lab 3 ECDSA written with py_ecc, following the equations in the Lab 3 handout.

Used only to cross-check app.crypto in tests: py_ecc is pure Python and not
constant-time, so it never handles real keys. Unlike the lab code, the private
key and nonce come from `secrets`, not `random`.
"""

from __future__ import annotations

import hashlib
import secrets
from dataclasses import dataclass

from py_ecc.secp256k1.secp256k1 import G, N, P, add, multiply

Point = tuple[int, int]


@dataclass(frozen=True)
class VerificationTrace:
    """Intermediate values of equations (5)-(7), handy for checking by hand."""

    w: int
    u1: int
    u2: int
    x: Point
    valid: bool


def hash_message(message: bytes) -> int:
    """Equation (2): z = SHA-256(M) read as an integer."""
    return int.from_bytes(hashlib.sha256(message).digest(), "big")


def public_key(d: int) -> Point:
    """Equation (1): Q = d * G."""
    return multiply(G, d)


def sign_message(d: int, z: int) -> tuple[int, int]:
    """Equations (3)-(4), repeated while r == 0 or s == 0."""
    while True:
        k = secrets.randbelow(N - 1) + 1
        r = multiply(G, k)[0] % N
        s = pow(k, -1, N) * (z + r * d) % N
        if r and s:
            return r, s


def verify_signature(q: Point, r: int, s: int, z: int) -> VerificationTrace:
    """Equations (5)-(7): valid iff r = x_X (mod N)."""
    if not (1 <= r < N and 1 <= s < N):
        return VerificationTrace(0, 0, 0, (0, 0), False)
    w = pow(s, -1, N)
    u1 = z * w % N
    u2 = r * w % N
    x = add(multiply(G, u1), multiply(q, u2))
    return VerificationTrace(w, u1, u2, x, x is not None and x[0] % N == r)


def decompress(data: bytes) -> Point:
    """Recover y from a 33-byte compressed key: y^2 = x^3 + 7 (mod P)."""
    x = int.from_bytes(data[1:], "big")
    y = pow((x**3 + 7) % P, (P + 1) // 4, P)
    if (y * y - x**3 - 7) % P:
        raise ValueError("x is not on the curve")
    return (x, y) if y % 2 == data[0] - 2 else (x, P - y)


def compress(point: Point) -> bytes:
    x, y = point
    return bytes([2 + (y % 2)]) + x.to_bytes(32, "big")


def is_on_curve(point: Point) -> bool:
    x, y = point
    return (y * y - x**3 - 7) % P == 0
