import os
from fastapi import Header, HTTPException, status
from jose import jwt, JWTError

_JWT_SECRET = os.getenv("JWT_SECRET", "")
_JWT_ALGORITHM = os.getenv("JWT_ALGORITHM", "HS256")


async def verify_token(
    authorization: str = Header(...)
) -> bool:
    """
    Verify the Bearer token on every request.
    Accepts JWT tokens issued by /auth/login
    or /auth/register.

    Fallback: if JWT_SECRET is empty, allows
    any token (dev mode only).
    """
    if not authorization.startswith("Bearer "):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authorization format"
        )

    token = authorization.replace("Bearer ", "")

    if not _JWT_SECRET:
        # Dev mode — no JWT configured
        return True

    try:
        payload = jwt.decode(
            token,
            _JWT_SECRET,
            algorithms=[_JWT_ALGORITHM],
        )
        if payload.get("sub"):
            return True
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token"
        )
    except JWTError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token"
        )
