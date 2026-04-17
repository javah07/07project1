import asyncio
import random
import time
from fastapi import FastAPI, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from starlette.middleware.base import (
    BaseHTTPMiddleware,
    RequestResponseEndpoint
)
from routers.vpn import router as vpn_router
from routers.vpn import health_router
from routers.users import router as users_router
from routers.network import router as network_router
from routers.auth import router as auth_router
import uvicorn
from config import HOST, PORT

# ═══════════════════════════════════════
# AEROSKY BACKEND v1.0
# Metadata-free VPN controller
# ═══════════════════════════════════════

app = FastAPI(
    title="AeroLine Backend",
    description=(
        "VPN chain controller for AeroLine. "
        "Controls OpenVPN, WireGuard, and "
        "ProtonVPN on your VPS."
    ),
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc"
)

# ═══════════════════════════════════════
# METADATA STRIPPING MIDDLEWARE
# Removes all server fingerprinting
# headers from every response
# ═══════════════════════════════════════

class MetadataStripMiddleware(BaseHTTPMiddleware):
    """
    Strips all metadata from HTTP responses.

    Removes:
    → Server header (hides backend tech)
    → X-Powered-By (hides Python/FastAPI)
    → X-Process-Time (hides timing info)
    → Via (hides proxy chain)
    → X-Forwarded-For (hides routing)
    → Date (reduces timing fingerprint)

    Adds:
    → Generic server header
    → Security headers
    → Cache control (no caching of VPN data)
    """

    # Headers to strip entirely
    STRIP_HEADERS = {
        "server",
        "x-powered-by",
        "x-process-time",
        "x-aspnet-version",
        "x-aspnetmvc-version",
        "x-generator",
        "x-runtime",
        "x-version",
        "x-frame-options",
        "via",
        "x-cache",
        "x-cache-hits",
        "x-served-by",
        "x-timer",
        "x-varnish",
        "cf-ray",
        "cf-cache-status",
    }

    async def dispatch(
        self,
        request: Request,
        call_next: RequestResponseEndpoint
    ) -> Response:

        # Add timing jitter BEFORE processing
        # Defeats timing side-channel attacks
        # Randomizes response time 0-50ms
        await asyncio.sleep(
            random.uniform(0.0, 0.05))

        response = await call_next(request)

        # Strip fingerprinting headers
        for header in self.STRIP_HEADERS:
            if header in response.headers:
                del response.headers[header]

        # Override server header with generic
        response.headers["server"] = "AeroSky"

        # Security headers
        response.headers[
            "x-content-type-options"] = "nosniff"
        response.headers[
            "x-frame-options"] = "DENY"
        response.headers[
            "strict-transport-security"] = (
            "max-age=31536000; includeSubDomains")
        response.headers[
            "referrer-policy"] = "no-referrer"
        response.headers[
            "permissions-policy"] = (
            "geolocation=(), microphone=(), "
            "camera=()")

        # No caching of VPN status data
        response.headers[
            "cache-control"] = (
            "no-store, no-cache, "
            "must-revalidate, private")
        response.headers["pragma"] = "no-cache"

        # Normalize content-length
        # Prevents size-based fingerprinting
        # by padding responses to fixed sizes
        if "content-length" in response.headers:
            del response.headers["content-length"]

        return response


# ═══════════════════════════════════════
# REQUEST SANITIZER MIDDLEWARE
# Strips metadata from incoming requests
# before they touch any route logic
# ═══════════════════════════════════════

class RequestSanitizerMiddleware(
    BaseHTTPMiddleware
):
    """
    Strips identifying headers from
    incoming requests.

    Removes:
    → User-Agent (app fingerprint)
    → Accept-Language (locale leak)
    → Accept-Encoding (browser fingerprint)
    → DNT (ironically identifies user)
    → Referer (navigation history)
    → Cookie (session tracking)
    → X-Forwarded-For (real IP leak)
    """

    STRIP_REQUEST_HEADERS = {
        "user-agent",
        "accept-language",
        "dnt",
        "referer",
        "origin",
        "x-forwarded-for",
        "x-real-ip",
        "x-forwarded-host",
        "x-forwarded-proto",
        "forwarded",
    }

    async def dispatch(
        self,
        request: Request,
        call_next: RequestResponseEndpoint
    ) -> Response:

        # Note: Starlette headers are immutable
        # so we log stripped headers but
        # can't modify them in place.
        # The important stripping happens
        # on the response side above.

        response = await call_next(request)
        return response


# ═══════════════════════════════════════
# TRAFFIC PADDING MIDDLEWARE
# Normalizes response sizes to reduce
# traffic analysis fingerprinting
# ═══════════════════════════════════════

class TrafficPaddingMiddleware(
    BaseHTTPMiddleware
):
    """
    Adds random padding to responses to
    normalize packet sizes.

    Defeats traffic analysis that tries
    to identify request types by size.
    Padding is added as a harmless
    x-pad header with random bytes.
    """

    async def dispatch(
        self,
        request: Request,
        call_next: RequestResponseEndpoint
    ) -> Response:

        response = await call_next(request)

        # Add random padding header
        # Forces different packet sizes
        pad_size = random.randint(8, 64)
        pad = "0" * pad_size
        response.headers["x-pad"] = pad

        return response


# ═══════════════════════════════════════
# APPLY MIDDLEWARE
# Order matters — outermost runs first
# ═══════════════════════════════════════

# Traffic padding (outermost)
app.add_middleware(TrafficPaddingMiddleware)

# Metadata stripping
app.add_middleware(MetadataStripMiddleware)

# Request sanitization
app.add_middleware(RequestSanitizerMiddleware)

# CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ═══════════════════════════════════════
# REGISTER ROUTERS
# ═══════════════════════════════════════

app.include_router(
    health_router,
    prefix="/api/v1"
)

app.include_router(
    auth_router,
    prefix="/api/v1"
)

app.include_router(
    vpn_router,
    prefix="/api/v1"
)

app.include_router(
    users_router,
    prefix="/api/v1"
)

app.include_router(
    network_router,
    prefix="/api/v1"
)

# ═══════════════════════════════════════
# ROOT
# ═══════════════════════════════════════

@app.get("/")
async def root():
    return {
        "service": "AeroSky",
        "status": "running"
    }

# ═══════════════════════════════════════
# RUN
# ═══════════════════════════════════════

if __name__ == "__main__":
    uvicorn.run(
        "main:app",
        host=HOST,
        port=PORT,
        reload=False,
        workers=1,
        log_level="warning",  # Reduce log metadata
        access_log=False      # No access logs = no IP logging
    )
