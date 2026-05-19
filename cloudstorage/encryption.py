"""
AES-GCM Encryption Engine
===========================
Replaces the original AES-128-ECB pipeline with AES-GCM, which provides
both confidentiality AND authenticated integrity (tamper detection) in a
single pass — no extra HMAC step required.

Supported key sizes
-------------------
* 16 bytes → AES-128-GCM
* 32 bytes → AES-256-GCM

Nonce
-----
A 96-bit (12-byte) random nonce is generated per encryption call and must
be stored alongside the ciphertext so it can be supplied at decryption.
The nonce is NOT secret; it just has to be unique per (key, message) pair.

Authentication tag
------------------
cryptography's AESGCM appends a 128-bit GCM authentication tag to the
ciphertext.  Decryption raises ``cryptography.exceptions.InvalidTag``
automatically when the tag does not verify — catching that exception lets
callers distinguish a wrong password from a corrupted ciphertext.
"""

import os

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidTag  # re-exported for callers

__all__ = [
    'derive_key',
    'encrypt_file_gcm',
    'decrypt_file_gcm',
    'InvalidTag',
]


def derive_key(raw_key: bytes, key_size: int) -> bytes:
    """
    Produce a key of exactly *key_size* bytes from an arbitrary-length
    password byte-string.

    If *raw_key* is longer than *key_size* it is truncated; if shorter it
    is right-padded with null bytes.  This keeps the approach simple and
    dependency-free (no KDF library needed) while matching the PoC scope.

    Parameters
    ----------
    raw_key : bytes
        The user-supplied password bytes.
    key_size : int
        Target byte length (16 for AES-128, 32 for AES-256).

    Returns
    -------
    bytes
        Exactly *key_size* bytes.
    """
    if len(raw_key) >= key_size:
        return raw_key[:key_size]
    return raw_key.ljust(key_size, b'\x00')


def encrypt_file_gcm(file_data: bytes, key: bytes) -> tuple:
    """
    Encrypt *file_data* with AES-GCM.

    Parameters
    ----------
    file_data : bytes
        Raw plaintext bytes to encrypt.
    key : bytes
        16- or 32-byte encryption key.

    Returns
    -------
    tuple[bytes, bytes]
        ``(ciphertext, nonce)`` where *ciphertext* includes the 16-byte
        GCM authentication tag appended by the library.
    """
    if len(key) not in (16, 32):
        raise ValueError(
            f"Key must be 16 or 32 bytes, got {len(key)}."
        )

    nonce = os.urandom(12)          # 96-bit random nonce (NIST recommended)
    aesgcm = AESGCM(key)
    ciphertext = aesgcm.encrypt(nonce, file_data, None)  # no additional data
    return ciphertext, nonce


def decrypt_file_gcm(ciphertext: bytes, nonce: bytes, key: bytes) -> bytes:
    """
    Decrypt AES-GCM ciphertext and verify its authentication tag.

    Parameters
    ----------
    ciphertext : bytes
        The ciphertext produced by :func:`encrypt_file_gcm` (includes tag).
    nonce : bytes
        The 12-byte nonce stored alongside the ciphertext.
    key : bytes
        16- or 32-byte decryption key (must match the one used at encryption).

    Returns
    -------
    bytes
        Decrypted plaintext.

    Raises
    ------
    cryptography.exceptions.InvalidTag
        If the key is wrong OR the ciphertext has been tampered with.
    """
    aesgcm = AESGCM(key)
    return aesgcm.decrypt(nonce, ciphertext, None)
