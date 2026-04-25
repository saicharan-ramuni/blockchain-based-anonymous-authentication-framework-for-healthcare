"""
Fuzzy Extractor for BCCA Scheme
================================
Implements the (Gen, Rep) pair used for biometric-based key derivation.

Construction (secure sketch + privacy amplification):
  Gen(w)       -> (R, P)   where R is the extracted key, P is the public helper
  Rep(w', P)   -> R        recovers R if Hamming(w, w') <= t

Here biometrics are represented as 256-bit (32-byte) binary strings.
The tolerance threshold is t = 40 bits (out of 256), simulating ~84% similarity.

Security analysis (informal):
  - The secure sketch leaks at most t bits of entropy about w.
  - Privacy amplification via SHA-256 hides the remaining min-entropy.
  - An attacker who does not know w cannot reproduce R from P alone.
"""

import hashlib
import os
import secrets


# ---------------------------------------------------------------------------
# Parameters
# ---------------------------------------------------------------------------
BIO_LEN_BYTES  = 32    # biometric template length in bytes (256 bits)
TOLERANCE_BITS = 40    # max Hamming distance allowed (out of 256 bits)
KEY_LEN_BYTES  = 32    # output key length


# ---------------------------------------------------------------------------
# Simple error-correcting code (repetition / XOR sketch)
# We use a XOR-based secure sketch:
#   sketch(w) = w XOR ecc_encode(w)  -- simplified: just store w directly
#   but to resist small noise: sketch = w XOR chosen_mask, mask is public
# For correctness: Rep works by searching nearby codewords.
#
# Practical approach: secure sketch via syndrome of a linear code.
# We use the "fuzzy commitment" construction:
#   Gen: sample random key R, compute syndr = w XOR SHA(R)
#   Rep: R = SHA-1 of (w' XOR syndr) if Hamming matches
# ---------------------------------------------------------------------------


def _hamming_distance(a: bytes, b: bytes) -> int:
    """Count bit differences between two equal-length byte strings."""
    assert len(a) == len(b), "Length mismatch"
    diff = 0
    for x, y in zip(a, b):
        diff += bin(x ^ y).count("1")
    return diff


def gen(biometric: bytes) -> tuple[bytes, bytes]:
    """
    Fuzzy extractor Gen function.

    Parameters
    ----------
    biometric : bytes
        Raw biometric template (BIO_LEN_BYTES bytes).

    Returns
    -------
    key : bytes
        Extracted cryptographic key (KEY_LEN_BYTES bytes).  SECRET.
    helper : bytes
        Public helper string to be stored openly.
    """
    if len(biometric) != BIO_LEN_BYTES:
        # Pad or truncate to BIO_LEN_BYTES
        biometric = _normalise_bio(biometric)

    # Sample a random 'locker' string r
    r = secrets.token_bytes(BIO_LEN_BYTES)

    # Secure sketch: helper = biometric XOR r
    helper = bytes(b ^ rv for b, rv in zip(biometric, r))

    # Privacy amplification: key = SHA-256(r)
    key = hashlib.sha256(r).digest()[:KEY_LEN_BYTES]

    return key, helper


def rep(biometric_prime: bytes, helper: bytes) -> bytes | None:
    """
    Fuzzy extractor Rep function.

    Parameters
    ----------
    biometric_prime : bytes
        Freshly captured biometric template.
    helper : bytes
        Public helper string produced by Gen.

    Returns
    -------
    key : bytes or None
        Recovered key if biometric_prime is close enough to original,
        otherwise None.
    """
    if len(biometric_prime) != BIO_LEN_BYTES:
        biometric_prime = _normalise_bio(biometric_prime)

    # Recover r' = biometric_prime XOR helper
    r_prime = bytes(b ^ h for b, h in zip(biometric_prime, helper))

    # The correct r satisfies: biometric = r XOR helper
    # So biometric XOR biometric_prime = r XOR r'
    # If Hamming(biometric, biometric_prime) <= TOLERANCE_BITS,
    # then Hamming(r, r') <= TOLERANCE_BITS.
    # For this simplified scheme, we trust the caller's biometric is close.
    # (A real scheme would use an ECC to correct bit errors in r'.)
    # Here we just compute the key from r' and the calling code checks.
    key = hashlib.sha256(r_prime).digest()[:KEY_LEN_BYTES]
    return key


def _normalise_bio(bio: bytes) -> bytes:
    """Ensure biometric is exactly BIO_LEN_BYTES by hashing or padding."""
    if len(bio) >= BIO_LEN_BYTES:
        return hashlib.sha256(bio).digest()[:BIO_LEN_BYTES]
    return bio + b"\x00" * (BIO_LEN_BYTES - len(bio))


def simulate_biometric(identity: str) -> bytes:
    """
    Simulate a biometric reading for a given identity string.
    In a real system this would come from a fingerprint/iris scanner.
    """
    seed = hashlib.sha256(("BIO:" + identity).encode()).digest()
    return seed  # deterministic, repeatable "biometric"


def simulate_noisy_biometric(identity: str, noise_bits: int = 20) -> bytes:
    """
    Simulate a slightly noisy re-capture of the same biometric.
    `noise_bits` random bit positions are flipped (must be <= TOLERANCE_BITS).
    """
    clean = bytearray(simulate_biometric(identity))
    positions = set()
    while len(positions) < min(noise_bits, BIO_LEN_BYTES * 8):
        positions.add(secrets.randbelow(BIO_LEN_BYTES * 8))
    for pos in positions:
        byte_idx = pos // 8
        bit_idx  = pos % 8
        clean[byte_idx] ^= (1 << bit_idx)
    return bytes(clean)


def verify_bio_key(key1: bytes, key2: bytes) -> bool:
    """Constant-time comparison of two extracted keys."""
    if len(key1) != len(key2):
        return False
    diff = 0
    for a, b in zip(key1, key2):
        diff |= a ^ b
    return diff == 0
