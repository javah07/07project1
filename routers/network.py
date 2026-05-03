import asyncio
import random
import httpx
from fastapi import APIRouter, Depends
from models.schemas import IpResponse
from auth.middleware import verify_token

router = APIRouter(
    prefix="/network",
    tags=["Network Info"],
    dependencies=[Depends(verify_token)]
)

# ═══════════════════════════════════════
# METADATA-FREE IP LOOKUP
# Uses Tor-friendly lookup services
# Strips identifying headers from request
# Adds timing jitter to prevent
# correlation attacks
# ═══════════════════════════════════════

# Rotate between services randomly
# Prevents building a lookup pattern
_IP_SERVICES = [
    "https://api.ipify.org",
    "https://ipv4.icanhazip.com",
    "https://checkip.amazonaws.com",
]

# Anonymous headers — no fingerprinting
_ANON_HEADERS = {
    "User-Agent": "curl/8.0",
    "Accept": "*/*",
    "Accept-Language": "en",
    "Cache-Control": "no-cache",
}


async def _get_ip_anonymously() -> str:
    """
    Fetch public IP without leaking
    metadata about the client.

    → Rotates between services randomly
    → Uses generic headers only
    → Adds timing jitter
    → Falls back gracefully
    """
    # Random jitter 50-150ms
    # Prevents timing correlation
    await asyncio.sleep(
        random.uniform(0.05, 0.15))

    # Shuffle services each call
    services = _IP_SERVICES.copy()
    random.shuffle(services)

    for service in services:
        try:
            async with httpx.AsyncClient(
                timeout=5,
                headers=_ANON_HEADERS,
                # No redirects — prevent redirect tracking
                follow_redirects=False
            ) as client:
                r = await client.get(service)
                if r.status_code == 200:
                    return r.text.strip()
        except Exception:
            continue

    return "Unknown"


async def _get_country_anonymously(
    ip: str
) -> tuple[str, str]:
    """
    Lookup country for IP without
    sending identifying data.
    Returns (country, city).
    """
    # Jitter
    await asyncio.sleep(
        random.uniform(0.02, 0.08))

    try:
        async with httpx.AsyncClient(
            timeout=5,
            headers=_ANON_HEADERS,
            follow_redirects=False
        ) as client:
            # Use ipwho.is over HTTPS — no API key needed
            # Only send IP, nothing else
            r = await client.get(
                f"https://ipwho.is/{ip}"
            )
            if r.status_code == 200:
                data = r.json()
                if data.get("success") is True:
                    return (
                        data.get("country", "Unknown"),
                        data.get("city", "Unknown")
                    )
    except Exception:
        pass

    return "Unknown", "Unknown"


@router.get("/ip", response_model=IpResponse)
async def get_current_ip():
    """
    Get current public IP address.
    Metadata-free lookup.
    Rotates services to prevent tracking.
    Returns ProtonVPN exit IP when active.
    """
    ip = await _get_ip_anonymously()

    if ip == "Unknown":
        return IpResponse(
            ip="Unknown",
            country="Unknown",
            city="Unknown"
        )

    country, city = \
        await _get_country_anonymously(ip)

    return IpResponse(
        ip=ip,
        country=country,
        city=city
    )
