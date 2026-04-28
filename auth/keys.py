import os
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend

_KEY_DIR = os.getenv("KEY_DIR", "/etc/aerosky/keys")
_PRIVATE_PATH = f"{_KEY_DIR}/private.pem"
_PUBLIC_PATH = f"{_KEY_DIR}/public.pem"

_RSA_PRIVATE_KEY = None
_RSA_PUBLIC_KEY = None


def _ensure_keys():
    global _RSA_PRIVATE_KEY, _RSA_PUBLIC_KEY
    if _RSA_PRIVATE_KEY is not None:
        return

    os.makedirs(_KEY_DIR, exist_ok=True)

    if os.path.exists(_PRIVATE_PATH) and os.path.exists(_PUBLIC_PATH):
        with open(_PRIVATE_PATH, "rb") as f:
            _RSA_PRIVATE_KEY = serialization.load_pem_private_key(
                f.read(), password=None, backend=default_backend()
            )
        with open(_PUBLIC_PATH, "rb") as f:
            _RSA_PUBLIC_KEY = serialization.load_pem_private_key(
                f.read(), password=None, backend=default_backend()
            )
    else:
        pk = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        _RSA_PRIVATE_KEY = pk
        _RSA_PUBLIC_KEY = pk.public_key()

        with open(_PRIVATE_PATH, "wb") as f:
            f.write(_RSA_PRIVATE_KEY.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption()
            ))
        os.chmod(_PRIVATE_PATH, 0o600)

        with open(_PUBLIC_PATH, "wb") as f:
            f.write(_RSA_PUBLIC_KEY.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ))
        os.chmod(_PUBLIC_PATH, 0o644)

    _RSA_PUBLIC_KEY = _RSA_PUBLIC_KEY.public_key()


def get_public_key_pem() -> bytes:
    """Returns PEM-encoded public key for JWT verification."""
    _ensure_keys()
    return _RSA_PUBLIC_KEY.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
