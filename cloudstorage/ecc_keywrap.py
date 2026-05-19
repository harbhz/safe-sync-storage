"""
ECIES-based DEK Key-Wrapping Engine
=====================================
Implements the ECC key-protection layer described in the Adaptive
Cryptographic Engine design:

  1. A fresh random Data Encryption Key (DEK) is generated per file.
  2. The DEK is *wrapped* (encrypted) with the file owner's ECC public key
     so the server never sees the DEK in plaintext — zero-knowledge.
  3. On download the owner uses their ECC private key to *unwrap* the DEK,
     then decrypts the file locally.

Scheme: ECIES — Elliptic Curve Integrated Encryption Scheme
  • Curve        : SECP256R1 (P-256) — NIST-recommended, wide support
  • Key exchange : ECDH (one-pass, ephemeral sender key)
  • KDF          : HKDF-SHA-256 → 256-bit AES wrapping key
  • DEK wrap     : AES-256-GCM (confidentiality + authenticity)

Why ECC over RSA for key wrapping?
  • Shorter keys (256-bit ECC ≈ 3072-bit RSA security)
  • Faster key generation and operations
  • Native support in the existing `cryptography` library
"""

import os

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ec import (
    EllipticCurvePrivateKey,
    EllipticCurvePublicKey,
)
from cryptography.hazmat.primitives.asymmetric.ec import ECDH
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.exceptions import InvalidTag  # noqa: F401 — re-exported

__all__ = [
    'generate_ecc_keypair',
    'wrap_dek',
    'unwrap_dek',
    'generate_dek',
    'InvalidTag',
]

_CURVE = ec.SECP256R1()
_HKDF_INFO = b'safesync-dek-wrap-v1'


# ---------------------------------------------------------------------------
# Key pair generation
# ---------------------------------------------------------------------------

def generate_ecc_keypair() -> tuple:
    """
    Generate a fresh SECP256R1 ECC key pair.

    Returns
    -------
    tuple[str, str]
        ``(private_key_pem, public_key_pem)`` — both as PEM strings.
        The private key is returned **unencrypted**; the caller is
        responsible for displaying it to the user exactly once and
        never persisting it server-side.
    """
    private_key = ec.generate_private_key(_CURVE, default_backend())

    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode()

    public_pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode()

    return private_pem, public_pem


# ---------------------------------------------------------------------------
# DEK generation
# ---------------------------------------------------------------------------

def generate_dek(key_size: int = 32) -> bytes:
    """
    Generate a cryptographically random Data Encryption Key.

    Parameters
    ----------
    key_size : int
        16 (AES-128) or 32 (AES-256). Defaults to 32.
    """
    if key_size not in (16, 32):
        raise ValueError(f"key_size must be 16 or 32, got {key_size}.")
    return os.urandom(key_size)


# ---------------------------------------------------------------------------
# ECIES key wrapping
# ---------------------------------------------------------------------------

def wrap_dek(dek: bytes, recipient_public_pem: str) -> dict:
    """
    Wrap (encrypt) a DEK using the recipient's ECC public key (ECIES).

    Process
    -------
    1. Generate an ephemeral EC key pair.
    2. ECDH between ephemeral private key and recipient public key → shared secret.
    3. HKDF-SHA-256 to derive a 256-bit AES wrapping key.
    4. AES-256-GCM encrypt the DEK → wrapped DEK + wrap nonce.
    5. Discard the ephemeral private key; store only the ephemeral public key
       alongside the wrapped DEK so the recipient can reproduce the shared secret.

    Parameters
    ----------
    dek : bytes
        The plaintext Data Encryption Key to wrap.
    recipient_public_pem : str
        PEM-encoded ECC public key of the file owner.

    Returns
    -------
    dict with keys:
        ``ephemeral_public_pem`` : str   — ephemeral EC public key (PEM)
        ``wrapped_dek``          : bytes — AES-GCM ciphertext of DEK (includes tag)
        ``wrap_nonce``           : bytes — 12-byte nonce used during wrapping
    """
    recipient_pub = serialization.load_pem_public_key(
        recipient_public_pem.encode(), backend=default_backend()
    )
    if not isinstance(recipient_pub, EllipticCurvePublicKey):
        raise TypeError("recipient_public_pem must encode an ECC public key")

    # Ephemeral sender key pair
    ephemeral_priv = ec.generate_private_key(_CURVE, default_backend())
    ephemeral_pub = ephemeral_priv.public_key()

    # ECDH shared secret
    shared_secret = ephemeral_priv.exchange(ECDH(), recipient_pub)

    # KDF: shared secret → AES-256 wrapping key
    wrapping_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=_HKDF_INFO,
        backend=default_backend(),
    ).derive(shared_secret)

    # Wrap DEK with AES-256-GCM
    wrap_nonce = os.urandom(12)
    aesgcm = AESGCM(wrapping_key)
    wrapped_dek = aesgcm.encrypt(wrap_nonce, dek, None)

    ephemeral_public_pem = ephemeral_pub.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode()

    return {
        'ephemeral_public_pem': ephemeral_public_pem,
        'wrapped_dek': wrapped_dek,
        'wrap_nonce': wrap_nonce,
    }


# ---------------------------------------------------------------------------
# ECIES key unwrapping
# ---------------------------------------------------------------------------

def unwrap_dek(
    ephemeral_public_pem: str,
    wrapped_dek: bytes,
    wrap_nonce: bytes,
    recipient_private_pem: str,
) -> bytes:
    """
    Unwrap (decrypt) a DEK using the recipient's ECC private key (ECIES).

    Parameters
    ----------
    ephemeral_public_pem : str
        The ephemeral EC public key stored alongside the wrapped DEK.
    wrapped_dek : bytes
        The AES-GCM ciphertext of the DEK (includes GCM tag).
    wrap_nonce : bytes
        The 12-byte nonce used during wrapping.
    recipient_private_pem : str
        PEM-encoded ECC private key of the file owner (never sent to server).

    Returns
    -------
    bytes
        Plaintext DEK, ready to pass to ``decrypt_file_gcm``.

    Raises
    ------
    cryptography.exceptions.InvalidTag
        If the private key is wrong or the wrapped DEK was tampered with.
    ValueError
        If the PEM data is malformed.
    """
    recipient_priv = serialization.load_pem_private_key(
        recipient_private_pem.encode(),
        password=None,
        backend=default_backend(),
    )
    if not isinstance(recipient_priv, EllipticCurvePrivateKey):
        raise TypeError("recipient_private_pem must encode an ECC private key")
    ephemeral_pub = serialization.load_pem_public_key(
        ephemeral_public_pem.encode(), backend=default_backend()
    )
    if not isinstance(ephemeral_pub, EllipticCurvePublicKey):
        raise TypeError("ephemeral_public_pem must encode an ECC public key")

    # Reproduce the shared secret
    shared_secret = recipient_priv.exchange(ECDH(), ephemeral_pub)

    # Reproduce the wrapping key via the same KDF
    wrapping_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=_HKDF_INFO,
        backend=default_backend(),
    ).derive(shared_secret)

    # Unwrap: AES-256-GCM decrypt
    aesgcm = AESGCM(wrapping_key)
    return aesgcm.decrypt(wrap_nonce, wrapped_dek, None)
