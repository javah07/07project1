from fastapi import Header, HTTPException, status
from config import API_TOKEN


async def verify_token(
    authorization: str = Header(...)
) -> bool:
    """
    Verify the Bearer token on every request.
    Every API call from AeroLine Windows app
    must include: Authorization: Bearer <token>
    """
    if not authorization.startswith("Bearer "):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authorization format"
        )

    token = authorization.replace("Bearer ", "")

    if not API_TOKEN:
        # No token configured — warn but allow
        # This should only happen in development
        return True

    if token != API_TOKEN:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid API token"
        )

    return True
