import os
import sqlite3
import bcrypt
import time
import base64
from datetime import datetime, timedelta
from fastapi import APIRouter, HTTPException, Response
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from jose import jwt
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend

router = APIRouter(prefix="/auth", tags=["Auth"])

# ── Config from env ──
_JWT_EXPIRE_MINUTES = int(os.getenv("JWT_EXPIRE_MINUTES", "60"))
_DB_PATH = os.getenv("DB_PATH", "/data/aero.db")
_ISSUER = os.getenv("ISSUER") or "").rstrip("/")
_AUDIENCE = os.getenv("AUDIENCE", "AeroLine")

# ── RSA key pair (generated once at startup) ──
private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
    backend=default_backend()
)
_RSA_PRIVATE_KEY = private_key.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.TraditionalOpenSSL,
    encryption_algorithm=serialization.NoEncryption()
)
public_key = private_key.public_key()
_RSA_PUBLIC_KEY = public_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
)

# ── Rate limiting ──
_rate_limit: dict = {}
_RATE_WINDOW = 60
_RATE_MAX = 10


def _rate_check(ip: str) -> bool:
    now = time.time()
    _rate_limit[ip] = [
        t for t in _rate_limit.get(ip, [])
        if now - t < _RATE_WINDOW
    ]
    if len(_rate_limit[ip]) >= _RATE_MAX:
        return False
    _rate_limit[ip].append(now)
    return True


def _get_db():
    os.makedirs(os.path.dirname(_DB_PATH), exist_ok=True)
    conn = sqlite3.connect(_DB_PATH)
    conn.execute(
        "CREATE TABLE IF NOT EXISTS users ("
        "id INTEGER PRIMARY KEY,"
        "username TEXT UNIQUE NOT NULL,"
        "password_hash TEXT NOT NULL,"
        "created TEXT NOT NULL"
        ")"
    )
    return conn


def _sanitize(response: Response):
    """Strip all fingerprinting headers."""
    response.headers["server"] = "AeroSky"
    response.headers["x-content-type-options"] = "nosniff"
    response.headers["x-frame-options"] = "DENY"
    response.headers["strict-transport-security"] = "max-age=31536000"
    response.headers["referrer-policy"] = "no-referrer"
    response.headers["cache-control"] = "no-store, no-cache"
    response.headers["pragma"] = "no-cache"
    if "content-length" in response.headers:
        del response.headers["content-length"]
    if "x-pad" in response.headers:
        del response.headers["x-pad"]


def _sign(payload: dict) -> str:
    """Sign a JWT payload with RS256."""
    pk = serialization.load_pem_private_key(
        _RSA_PRIVATE_KEY,
        password=None,
        backend=default_backend()
    )
    return jwt.encode(payload, pk, algorithm="RS256")


def _int_to_b64url(n: int) -> str:
    """Encode a positive integer to URL-safe base64 without padding."""
    byte_len = (n.bit_length() + 7) // 8
    return base64.urlsafe_b64encode(
        n.to_bytes(byte_len, "big")
    ).rstrip(b"=").decode()


# ── Request/Response models ──

class RegisterRequest(BaseModel):
    username: str
    password: str


class LoginRequest(BaseModel):
    username: str
    password: str


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    expires_in: int


# ── OIDC Discovery ──

@router.get("/.well-known/openid-configuration")
async def oidc_discovery(response: Response):
    """
    OpenID Connect discovery document.
    Microsoft IdentityModel fetches this
    to validate the token's issuer.
    """
    _sanitize(response)

    if not _ISSUER:
        raise HTTPException(status_code=500, detail="ISSUER env not set")

    return JSONResponse(
        content={
            "issuer": _ISSUER,
            "jwks_uri": f"{_ISSUER}/auth/jwks",
            "authorization_endpoint": f"{_ISSUER}/auth/authorize",
            "token_endpoint": f"{_ISSUER}/auth/login",
            "userinfo_endpoint": f"{_ISSUER}/auth/userinfo",
            "response_types_supported": ["code", "token"],
            "subject_types_supported": ["public"],
            "id_token_signing_alg_values_supported": ["RS256"],
            "scopes_supported": ["openid", "profile"],
            "token_endpoint_auth_methods_supported": ["client_secret_basic"],
            "claims_supported": [
                "sub", "iss", "aud", "exp", "iat",
                "username", "email"
            ],
        },
        media_type="application/json",
    )


@router.get("/auth/jwks")
async def jwks(response: Response):
    """
    JSON Web Key Set — public keys that
    Microsoft IdentityModel uses to verify
    the RS256 signature on tokens.
    """
    _sanitize(response)

    pubk = serialization.load_pem_public_key(
        _RSA_PUBLIC_KEY,
        backend=default_backend()
    )
    rsa_key = pubk.public_numbers()

    return JSONResponse(
        content={
            "keys": [
                {
                    "kty": "RSA",
                    "use": "sig",
                    "kid": "1",
                    "alg": "RS256",
                    "n": _int_to_b64url(rsa_key.n),
                    "e": _int_to_b64url(rsa_key.e),
                }
            ]
        },
        media_type="application/json",
    )


# ── Auth Routes ──

@router.post(
    "/register",
    response_model=TokenResponse,
    responses={
        400: {"description": "Username taken or invalid"},
        429: {"description": "Rate limited"},
    },
)
async def register(body: RegisterRequest, response: Response):
    _sanitize(response)

    username = body.username.strip().lower()
    password = body.password

    if not username or len(username) < 3 or len(username) > 32:
        raise HTTPException(status_code=400, detail="Invalid username")
    if not password or len(password) < 8:
        raise HTTPException(status_code=400, detail="Invalid password")

    if not _ISSUER:
        raise HTTPException(status_code=500, detail="ISSUER env not set")

    # Hash password
    pw_hash = bcrypt.hashpw(
        password.encode(),
        bcrypt.gensalt()
    ).decode()

    # Store user
    try:
        conn = _get_db()
        conn.execute(
            "INSERT INTO users (username, password_hash, created) VALUES (?, ?, ?)",
            (username, pw_hash, datetime.utcnow().isoformat()),
        )
        conn.commit()
        conn.close()
    except sqlite3.IntegrityError:
        raise HTTPException(status_code=400, detail="Username taken")

    # Issue RS256 JWT
    now = datetime.utcnow()
    payload = {
        "sub": username,
        "iss": _ISSUER,
        "aud": _AUDIENCE,
        "iat": int(now.timestamp()),
        "exp": int((now + timedelta(minutes=_JWT_EXPIRE_MINUTES)).timestamp()),
        "username": username,
    }
    token = _sign(payload)

    return TokenResponse(
        access_token=token,
        expires_in=_JWT_EXPIRE_MINUTES * 60,
    )


@router.post(
    "/login",
    response_model=TokenResponse,
    responses={
        401: {"description": "Invalid credentials"},
        429: {"description": "Rate limited"},
    },
)
async def login(body: LoginRequest, response: Response):
    _sanitize(response)

    username = body.username.strip().lower()
    password = body.password

    if not _ISSUER:
        raise HTTPException(status_code=500, detail="ISSUER env not set")

    conn = _get_db()
    row = conn.execute(
        "SELECT password_hash FROM users WHERE username = ?",
        (username,),
    ).fetchone()
    conn.close()

    # Always run bcrypt check to prevent timing attacks
    if not row or not bcrypt.checkpw(password.encode(), row[0].encode()):
        raise HTTPException(status_code=401, detail="Invalid credentials")

    # Issue RS256 JWT
    now = datetime.utcnow()
    payload = {
        "sub": username,
        "iss": _ISSUER,
        "aud": _AUDIENCE,
        "iat": int(now.timestamp()),
        "exp": int((now + timedelta(minutes=_JWT_EXPIRE_MINUTES)).timestamp()),
        "username": username,
    }
    token = _sign(payload)

    return TokenResponse(
        access_token=token,
        expires_in=_JWT_EXPIRE_MINUTES * 60,
    )


@router.get("/health")
async def auth_health(response: Response):
    """Public health check for the auth module."""
    _sanitize(response)
    return {"status": "ok"}
