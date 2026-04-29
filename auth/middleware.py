import os
from fastapi import Header, HTTPException, status
from jose import jwt, JWTError
from auth.keys import get_public_pem

_JWT_ALGORITHM = "RS256"
_AUDIENCE = os.getenv("AUDIENCE", "AeroLine")
_ISSUER = (os.getenv("ISSUER") or "").rstrip("/")


async def verify_token(
    authorization: str = Header(...)
) -> bool:
    """
    Verify RS256 JWT Bearer token.

    Tokens are signed with persistent
    RSA private key on server.
    Verified here with matching public key.

    Both must use same key pair —
    keys.py ensures this by persisting
    the key pair to disk.
    """
    if not authorization.startswith("Bearer "):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authorization format"
        )

    token = authorization.removeprefix("Bearer ")

    # Dev mode — no issuer configured
    if not _ISSUER:
        return True

    try:
        public_pem = get_public_pem()

        payload = jwt.decode(
            token,
            public_pem,
            algorithms=[_JWT_ALGORITHM],
            audience=_AUDIENCE,
            issuer=_ISSUER,
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
