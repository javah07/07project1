import os
import sqlite3
import bcrypt
import secrets
import time
from datetime import datetime, timedelta
from fastapi import APIRouter, HTTPException, Response
from pydantic import BaseModel
from jose import jwt, JWTError

router = APIRouter(prefix="/auth", tags=["Auth"])

# ── Config from env ──
_JWT_SECRET = os.getenv("JWT_SECRET", "")
_JWT_ALGORITHM = os.getenv("JWT_ALGORITHM", "HS256")
_JWT_EXPIRE_MINUTES = int(os.getenv("JWT_EXPIRE_MINUTES", "60"))
_DB_PATH = os.getenv("DB_PATH", "/data/aero.db")

# ── Rate limiting ──
_rate_limit: dict = {}
_RATE_WINDOW = 60
_RATE_MAX = 10


def _rate_check(ip: str) -> bool:
    now = time.time()
    _rate_limit[ip] = [t for t in _rate_limit.get(ip, []) if now - t < _RATE_WINDOW]
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
    """Strip all fingerprinting headers from response."""
    response.headers["server"] = "AeroSky"
    response.headers["x-content-type-options"] = "nosniff"
    response.headers["x-frame-options"] = "DENY"
    response.headers["strict-transport-security"] = "max-age=31536000"
    response.headers["referrer-policy"] = "no-referrer"
    response.headers["cache-control"] = "no-store"
    response.headers["pragma"] = "no-cache"
    if "content-length" in response.headers:
        del response.headers["content-length"]
    if "x-pad" in response.headers:
        del response.headers["x-pad"]


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


# ── Routes ──

@router.post(
    "/register",
    response_model=TokenResponse,
    responses={
        400: {"description": "Username taken"},
        429: {"description": "Rate limited"},
    },
)
async def register(body: RegisterRequest, response: Response):
    _sanitize(response)

    # Validate input
    username = body.username.strip().lower()
    password = body.password

    if not username or len(username) < 3 or len(username) > 32:
        raise HTTPException(status_code=400, detail="Invalid username")
    if not password or len(password) < 8:
        raise HTTPException(status_code=400, detail="Invalid password")

    # Hash password
    pw_hash = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()

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

    # Issue token
    exp = datetime.utcnow() + timedelta(minutes=_JWT_EXPIRE_MINUTES)
    token = jwt.encode(
        {"sub": username, "exp": exp},
        _JWT_SECRET,
        algorithm=_JWT_ALGORITHM,
    )

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

    conn = _get_db()
    row = conn.execute(
        "SELECT password_hash FROM users WHERE username = ?",
        (username,),
    ).fetchone()
    conn.close()

    # Always run bcrypt check to prevent timing attacks
    if not row or not bcrypt.checkpw(password.encode(), row[0].encode()):
        raise HTTPException(status_code=401, detail="Invalid credentials")

    exp = datetime.utcnow() + timedelta(minutes=_JWT_EXPIRE_MINUTES)
    token = jwt.encode(
        {"sub": username, "exp": exp},
        _JWT_SECRET,
        algorithm=_JWT_ALGORITHM,
    )

    return TokenResponse(
        access_token=token,
        expires_in=_JWT_EXPIRE_MINUTES * 60,
    )


@router.get("/health")
async def auth_health(response: Response):
    """Public health check for the auth module."""
    _sanitize(response)
    return {"status": "ok"}
