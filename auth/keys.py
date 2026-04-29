"""
AeroSky Persistent RSA Key Manager

Generates RSA-2048 key pair on first run
Saves to disk so tokens remain valid
across server restarts.

Without persistence:
→ New key every restart
→ All existing tokens invalid
→ Users logged out constantly

With persistence:
→ Same key always
→ Tokens valid for their lifetime
→ JWKS endpoint returns correct key
"""

import os
from pathlib import Path
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend

# Key storage location
_KEY_DIR = Path(
    os.getenv("KEY_DIR", "/etc/aerosky/keys"))
_PRIVATE_KEY_PATH = _KEY_DIR / "private.pem"
_PUBLIC_KEY_PATH = _KEY_DIR / "public.pem"

# Cached in memory after first load
_private_key = None
_public_key = None


def _generate_and_save():
    """Generate RSA-2048 key pair and save."""
    _KEY_DIR.mkdir(parents=True, exist_ok=True)
    os.chmod(_KEY_DIR, 0o700)

    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )

    # Save private key (owner read only)
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat
            .TraditionalOpenSSL,
        encryption_algorithm=
            serialization.NoEncryption()
    )
    _PRIVATE_KEY_PATH.write_bytes(private_pem)
    os.chmod(_PRIVATE_KEY_PATH, 0o600)

    # Save public key
    public_pem = private_key.public_key() \
        .public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat
                .SubjectPublicKeyInfo
        )
    _PUBLIC_KEY_PATH.write_bytes(public_pem)
    os.chmod(_PUBLIC_KEY_PATH, 0o644)

    return private_key


def get_private_key():
    """Get private key — load or generate."""
    global _private_key

    if _private_key is not None:
        return _private_key

    if _PRIVATE_KEY_PATH.exists():
        pem = _PRIVATE_KEY_PATH.read_bytes()
        _private_key = serialization \
            .load_pem_private_key(
                pem,
                password=None,
                backend=default_backend()
            )
    else:
        _private_key = _generate_and_save()

    return _private_key


def get_public_key():
    """Get public key — load or generate."""
    global _public_key

    if _public_key is not None:
        return _public_key

    # Ensure private key exists first
    get_private_key()

    if _PUBLIC_KEY_PATH.exists():
        pem = _PUBLIC_KEY_PATH.read_bytes()
        _public_key = serialization \
            .load_pem_public_key(
                pem,
                backend=default_backend()
            )
    else:
        _public_key = get_private_key() \
            .public_key()

    return _public_key


def get_public_pem() -> bytes:
    """Get public key as PEM bytes."""
    return get_public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat
            .SubjectPublicKeyInfo
    )
