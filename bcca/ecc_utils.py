"""
ECC Utilities for Healthcare BCCA Scheme
==========================================
Pure-Python implementation on secp256k1 curve (no external crypto deps).

Notation (from healthcare_ehr_scheme.md):
  G      - generator point (= P in paper)
  N      - group order q
  s      - HA master key
  P_pub  = s · G           (main public key)
  P_pub1 = s₁ · G          (H₂ domain key for EHR integrity)
  P_pub2 = s₂ · G          (H₃ domain key for temporal freshness)
  H₁, H₂, H₃ : {0,1}* → Z*_q
  H, H₅       : {0,1}* → Z*_q  (for mutual authentication)
"""

import hashlib
import secrets
import json


# ---------------------------------------------------------------------------
# secp256k1 curve parameters
# ---------------------------------------------------------------------------
_P  = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
_A  = 0
_B  = 7
_GX = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
_GY = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8
_N  = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141


class ECPoint:
    """A point on the secp256k1 elliptic curve, or the point at infinity."""

    __slots__ = ("x", "y")

    def __init__(self, x, y):
        self.x = x
        self.y = y

    def is_infinity(self):
        return self.x is None and self.y is None

    def __eq__(self, other):
        if not isinstance(other, ECPoint):
            return False
        return self.x == other.x and self.y == other.y

    def __repr__(self):
        if self.is_infinity():
            return "ECPoint(INF)"
        return f"ECPoint(x={self.x:#066x}, y={self.y:#066x})"

    def __add__(self, other: "ECPoint") -> "ECPoint":
        if self.is_infinity():
            return other
        if other.is_infinity():
            return self
        p = _P
        if self.x == other.x:
            if (self.y + other.y) % p == 0:
                return INF
            # Point doubling
            lam = (3 * self.x * self.x + _A) * pow(2 * self.y, p - 2, p) % p
        else:
            lam = (other.y - self.y) * pow(other.x - self.x, p - 2, p) % p
        x3 = (lam * lam - self.x - other.x) % p
        y3 = (lam * (self.x - x3) - self.y) % p
        return ECPoint(x3, y3)

    def __neg__(self) -> "ECPoint":
        if self.is_infinity():
            return self
        return ECPoint(self.x, (-self.y) % _P)

    def __sub__(self, other: "ECPoint") -> "ECPoint":
        return self + (-other)

    def __rmul__(self, scalar: int) -> "ECPoint":
        return self.__mul__(scalar)

    def __mul__(self, scalar: int) -> "ECPoint":
        """Double-and-add scalar multiplication."""
        scalar = int(scalar) % _N
        if scalar == 0 or self.is_infinity():
            return INF
        result = INF
        addend = ECPoint(self.x, self.y)
        while scalar:
            if scalar & 1:
                result = result + addend
            addend = addend + addend
            scalar >>= 1
        return result

    # ------------------------------------------------------------------
    # Serialisation
    # ------------------------------------------------------------------
    def to_bytes(self) -> bytes:
        """Uncompressed SEC encoding (65 bytes: 04 || x || y)."""
        if self.is_infinity():
            return b"\x00"
        return b"\x04" + self.x.to_bytes(32, "big") + self.y.to_bytes(32, "big")

    @staticmethod
    def from_bytes(data: bytes) -> "ECPoint":
        if data == b"\x00":
            return INF
        if len(data) != 65 or data[0] != 0x04:
            raise ValueError("Invalid point encoding")
        x = int.from_bytes(data[1:33], "big")
        y = int.from_bytes(data[33:], "big")
        return ECPoint(x, y)

    def to_dict(self) -> dict:
        if self.is_infinity():
            return {"x": None, "y": None}
        return {"x": self.x, "y": self.y}

    @staticmethod
    def from_dict(d: dict) -> "ECPoint":
        if d.get("x") is None:
            return INF
        return ECPoint(d["x"], d["y"])

    def to_hex(self) -> str:
        return self.to_bytes().hex()

    @staticmethod
    def from_hex(h: str) -> "ECPoint":
        return ECPoint.from_bytes(bytes.fromhex(h))


# Public constants
INF     = ECPoint(None, None)   # point at infinity
G       = ECPoint(_GX, _GY)    # generator  (= P in paper)
N       = _N                    # group order q
P_FIELD = _P                    # field prime


# ---------------------------------------------------------------------------
# Random scalar
# ---------------------------------------------------------------------------
def rand_scalar() -> int:
    """Return a cryptographically random scalar in [1, N-1]."""
    return secrets.randbelow(_N - 1) + 1


def modinv(a: int, m: int = _N) -> int:
    """Modular inverse using Fermat's little theorem (m must be prime)."""
    return pow(a, m - 2, m)


# ---------------------------------------------------------------------------
# Hash functions H₁, H₂, H₃, H, H₅
#
# Paper: Hi : {0,1}* → Z*_q
# Domain separation via distinct prefix bytes.
# ---------------------------------------------------------------------------

def _hash_to_scalar(domain: bytes, *items) -> int:
    """Hash multiple items to a non-zero scalar in Z*_N."""
    h = hashlib.sha256()
    h.update(domain)
    for item in items:
        if isinstance(item, ECPoint):
            b = item.to_bytes()
        elif isinstance(item, int):
            length = (item.bit_length() + 7) // 8 or 1
            b = item.to_bytes(length, "big")
        elif isinstance(item, (bytes, bytearray)):
            b = bytes(item)
        elif isinstance(item, str):
            b = item.encode("utf-8")
        else:
            b = str(item).encode("utf-8")
        h.update(len(b).to_bytes(4, "big"))
        h.update(b)
    val = int.from_bytes(h.digest(), "big") % _N
    return val if val != 0 else 1   # never return 0


def H1(*items) -> int:
    """General-purpose hash — used in Setup, Registration, Login, Partial Key,
    and EHR Verification (h_{1,i}). Maps {0,1}* → Z*_q."""
    return _hash_to_scalar(b"\x01HEALTHCARE-H1", *items)


def H2(*items) -> int:
    """EHR integrity binding hash — uses P_pub1 domain.
    h_{2,i} = H₂(ID_i, KID_{i,k}, Q_{i,k}, P_pub1)"""
    return _hash_to_scalar(b"\x02HEALTHCARE-H2", *items)


def H3(*items) -> int:
    """Temporal freshness binding hash — uses P_pub2 domain.
    h_{3,i} = H₃(c_i, pk_i, P_pub2, T_i)"""
    return _hash_to_scalar(b"\x03HEALTHCARE-H3", *items)


def H_auth(*items) -> int:
    """Session key derivation hash H: G → Z*_q  (mutual authentication step)."""
    return _hash_to_scalar(b"\x04HEALTHCARE-H", *items)


def H5(*items) -> int:
    """Session key derivation H₅: {0,1}* → Z*_q."""
    return _hash_to_scalar(b"\x05HEALTHCARE-H5", *items)


def Hgen(*items) -> int:
    """General hash used in chameleon hash and other contexts."""
    return _hash_to_scalar(b"\x00HEALTHCARE-HGEN", *items)


# ---------------------------------------------------------------------------
# XOR-based EHR encryption (stream from SHAKE-256)
# c_i = m_i ⊕ expand(ek_{i,k})
# ---------------------------------------------------------------------------

def xor_encrypt(plaintext: bytes, key_scalar: int) -> bytes:
    """
    XOR-encrypt plaintext with a keystream derived from key_scalar.
    key_scalar = H₁(q_{i,k} · dpk) as an integer.
    """
    key_bytes = key_scalar.to_bytes((key_scalar.bit_length() + 7) // 8 or 1, "big")
    # Expand to required length using SHAKE-256
    shake = hashlib.shake_256(b"EHR-ENC" + key_bytes)
    stream = shake.digest(len(plaintext))
    return bytes(a ^ b for a, b in zip(plaintext, stream))


def xor_decrypt(ciphertext: bytes, key_scalar: int) -> bytes:
    """XOR-decrypt (identical to encrypt since XOR is self-inverse)."""
    return xor_encrypt(ciphertext, key_scalar)


# ---------------------------------------------------------------------------
# Symmetric encryption helpers (for mutual auth payload C_a, C_b)
# Uses AES-256-GCM with key derived from scalar via SHA-256.
# ---------------------------------------------------------------------------

def sym_encrypt(key_scalar: int, plaintext: bytes) -> bytes:
    """AES-256-GCM encrypt using key derived from key_scalar."""
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    import os
    key_bytes = hashlib.sha256(key_scalar.to_bytes(32, "big")).digest()
    nonce = os.urandom(12)
    ct = AESGCM(key_bytes).encrypt(nonce, plaintext, None)
    return nonce + ct


def sym_decrypt(key_scalar: int, token: bytes) -> bytes:
    """AES-256-GCM decrypt."""
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    key_bytes = hashlib.sha256(key_scalar.to_bytes(32, "big")).digest()
    nonce, ct = token[:12], token[12:]
    return AESGCM(key_bytes).decrypt(nonce, ct, None)
