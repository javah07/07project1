import os
import sqlite3
import bcrypt
import time
import base64
from datetime import datetime, timedelta
from fastapi import APIRouter, HTTPException, Response, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from jose import jwt
from auth.keys import get_private_key, get_public_key

router = APIRouter(prefix="/auth", tags=["Auth"])

_JWT_EXPIRE_MINUTES = int(
    os.getenv("JWT_EXPIRE_MINUTES", "60"))
_DB_PATH = os.getenv("DB_PATH", "/data/aero.db")
_ISSUER = (os.getenv("ISSUER") or "").rstrip("/")
_AUDIENCE = os.getenv("AUDIENCE", "AeroLine")

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
    os.makedirs(
        os.path.dirname(_DB_PATH),
        exist_ok=True)
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


def _sign(payload: dict) -> str:
    """
    Sign JWT with PERSISTENT RSA private key.
    Same key every time = tokens stay valid.
    """
    private_key = get_private_key()

    private_pem = private_key.private_bytes(
        encoding=__import__('cryptography')
            .hazmat.primitives.serialization
            .Encoding.PEM,
        format=__import__('cryptography')
            .hazmat.primitives.serialization
            .PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=__import__(
            'cryptography')
            .hazmat.primitives.serialization
            .NoEncryption()
    )

    return jwt.encode(
        payload, private_pem, algorithm="RS256")


def _int_to_b64url(n: int) -> str:
    byte_len = (n.bit_length() + 7) // 8
    return base64.urlsafe_b64encode(
        n.to_bytes(byte_len, "big")
    ).rstrip(b"=").decode()


# ═══════════════════════════════════════
# SCHEMAS
# ═══════════════════════════════════════

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


# ═══════════════════════════════════════
# OIDC DISCOVERY
# ═══════════════════════════════════════

@router.get("/.well-known/openid-configuration")
async def oidc_discovery():
    if not _ISSUER:
        raise HTTPException(
            status_code=500,
            detail="ISSUER env not set")
    return JSONResponse(content={
        "issuer": _ISSUER,
        "jwks_uri": f"{_ISSUER}/api/v1/auth/jwks",
        "token_endpoint": f"{_ISSUER}/api/v1/auth/login",
        "response_types_supported": ["token"],
        "subject_types_supported": ["public"],
        "id_token_signing_alg_values_supported":
            ["RS256"],
    })


# ═══════════════════════════════════════
# JWKS — uses SAME persistent public key
# that tokens are signed with
# ═══════════════════════════════════════

@router.get("/jwks")
async def jwks():
    """
    Returns the persistent public key.
    Matches the private key used to sign tokens.
    """
    pub = get_public_key().public_numbers()
    return JSONResponse(content={
        "keys": [{
            "kty": "RSA",
            "use": "sig",
            "kid": "aerosky-1",
            "alg": "RS256",
            "n": _int_to_b64url(pub.n),
            "e": _int_to_b64url(pub.e),
        }]
    })


# ═══════════════════════════════════════
# REGISTER
# ═══════════════════════════════════════

@router.post(
    "/register",
    response_model=TokenResponse,
)
async def register(body: RegisterRequest, request: Request):
    client_ip = request.client.host if request.client else "unknown"
    if not _rate_check(client_ip):
        raise HTTPException(
            status_code=429,
            detail="Too many requests")

    username = body.username.strip().lower()
    password = body.password

    if not username or \
            len(username) < 3 or \
            len(username) > 32:
        raise HTTPException(
            status_code=400,
            detail="Invalid username")
    if not password or len(password) < 8:
        raise HTTPException(
            status_code=400,
            detail="Password too short")
    if not _ISSUER:
        raise HTTPException(
            status_code=500,
            detail="ISSUER env not set")

    pw_hash = bcrypt.hashpw(
        password.encode(),
        bcrypt.gensalt()
    ).decode()

    try:
        conn = _get_db()
        conn.execute(
            "INSERT INTO users "
            "(username, password_hash, created) "
            "VALUES (?, ?, ?)",
            (username, pw_hash,
             datetime.utcnow().isoformat()),
        )
        conn.commit()
        conn.close()
    except sqlite3.IntegrityError:
        raise HTTPException(
            status_code=400,
            detail="Username taken")

    return _issue_token(username)


# ═══════════════════════════════════════
# LOGIN
# ═══════════════════════════════════════

@router.post(
    "/login",
    response_model=TokenResponse,
)
async def login(body: LoginRequest, request: Request):
    client_ip = request.client.host if request.client else "unknown"
    if not _rate_check(client_ip):
        raise HTTPException(
            status_code=429,
            detail="Too many requests")

    username = body.username.strip().lower()
    password = body.password

    if not _ISSUER:
        raise HTTPException(
            status_code=500,
            detail="ISSUER env not set")

    conn = _get_db()
    row = conn.execute(
        "SELECT password_hash FROM users "
        "WHERE username = ?",
        (username,),
    ).fetchone()
    conn.close()

    if not row or not bcrypt.checkpw(
            password.encode(),
            row[0].encode()):
        raise HTTPException(
            status_code=401,
            detail="Invalid credentials")

    return _issue_token(username)


def _issue_token(username: str) -> TokenResponse:
    now = datetime.utcnow()
    payload = {
        "sub": username,
        "iss": _ISSUER,
        "aud": _AUDIENCE,
        "iat": int(now.timestamp()),
        "exp": int((
            now + timedelta(
                minutes=_JWT_EXPIRE_MINUTES)
        ).timestamp()),
        "username": username,
    }
    token = _sign(payload)
    return TokenResponse(
        access_token=token,
        expires_in=_JWT_EXPIRE_MINUTES * 60,
    )


# ═══════════════════════════════════════
# HEALTH
# ═══════════════════════════════════════

@router.get("/health")
async def auth_health():
    return {"status": "ok"}
