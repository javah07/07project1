from fastapi import FastAPI, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from routers.vpn import router as vpn_router
from routers.vpn import health_router
from routers.users import router as users_router
from routers.network import router as network_router
from routers.auth import router as auth_router
import uvicorn
from config import HOST, PORT

# ═══════════════════════════════════════
# AEROSKY BACKEND v1.0
# ═══════════════════════════════════════

app = FastAPI(
    title="AeroLine Backend",
    description=(
        "VPN chain controller for AeroSky, V1.1."
    ),
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc"
)

# ═══════════════════════════════════════
# FAST PURE ASGI MIDDLEWARE
# Replaces slow BaseHTTPMiddleware
# BaseHTTPMiddleware buffers entire
# response body — terrible on free tier
# Pure ASGI middleware is non-blocking
# ═══════════════════════════════════════

SECURITY_HEADERS = {
    "server": "AeroSky",
    "x-content-type-options": "nosniff",
    "x-frame-options": "DENY",
    "referrer-policy": "no-referrer",
    "cache-control": (
        "no-store, no-cache, "
        "must-revalidate, private"
    ),
    "pragma": "no-cache",
}

STRIP_HEADERS = {
    "x-powered-by",
    "x-process-time",
    "via",
    "x-cache",
    "x-varnish",
    "cf-ray",
    "content-length",  # prevents size fingerprint
}


class SecurityMiddleware:
    """
    Pure ASGI security middleware.
    Non-blocking — no response buffering.
    Strips fingerprinting headers.
    Adds security headers.
    10x faster than BaseHTTPMiddleware.
    """

    def __init__(self, app):
        self.app = app

    async def __call__(
        self, scope, receive, send
    ):
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        async def send_with_headers(message):
            if message["type"] == \
                    "http.response.start":
                headers = dict(
                    message.get("headers", []))

                # Strip fingerprinting
                for h in STRIP_HEADERS:
                    headers.pop(
                        h.encode(), None)

                # Add security headers
                for k, v in \
                        SECURITY_HEADERS.items():
                    headers[k.encode()] = \
                        v.encode()

                message = {
                    **message,
                    "headers": list(
                        headers.items())
                }

            await send(message)

        await self.app(
            scope, receive,
            send_with_headers)


# Apply fast ASGI middleware
app.add_middleware(CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Wrap with security middleware
app = SecurityMiddleware(app)

# Re-wrap with FastAPI for routing
# (SecurityMiddleware wraps the ASGI app)

# ═══════════════════════════════════════
# NOTE: Router registration must happen
# BEFORE SecurityMiddleware wrapping
# We use a factory pattern below
# ═══════════════════════════════════════

def create_app() -> FastAPI:
    _app = FastAPI(
        title="AeroLine Backend",
        version="1.0.0",
        docs_url="/docs",
        redoc_url="/redoc"
    )

    _app.add_middleware(CORSMiddleware,
        allow_origins=["*"],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    _app.include_router(
        health_router, prefix="/api/v1")
    _app.include_router(
        auth_router, prefix="/api/v1")
    _app.include_router(
        vpn_router, prefix="/api/v1")
    _app.include_router(
        users_router, prefix="/api/v1")
    _app.include_router(
        network_router, prefix="/api/v1")

    @_app.get("/")
    async def root():
        return {
            "service": "AeroSky",
            "status": "running"
        }

    return _app


# Create base FastAPI app
_base_app = create_app()

# Wrap with fast security middleware
app = SecurityMiddleware(_base_app)

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
        log_level="warning",
        access_log=False
    )
