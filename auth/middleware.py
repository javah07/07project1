import os
from fastapi import Header, HTTPException
from jose import jwt
from jose.exceptions import JWTError
from auth.keys import get_public_key_pem

_AUDIENCE = os.getenv("AUDIENCE", "AeroSky")
_ISSUER = (os.getenv("ISSUER") or "").rstrip("/")


async def verify_token(authorization: str = Header(...)) -> str:
    """
    Verify RS256 Bearer token.
    Returns username on success, raises HTTPException on failure.
    """
    if not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Invalid authorization format")

    token = authorization.replace("Bearer ", "")

    try:
        pub_key = get_public_key_pem()
        payload = jwt.decode(
            token,
            pub_key,
            algorithms=["RS256"],
            audience=_AUDIENCE,
            issuer=_ISSUER,
        )
        if payload.get("sub"):
            return payload["sub"]
        raise HTTPException(status_code=401, detail="Invalid token")
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid token")
