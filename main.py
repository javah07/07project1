import os
import uvicorn
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from routers.vpn import router as vpn_router, health_router
from routers.users import router as users_router
from routers.network import router as network_router
from routers.auth import router as auth_router
from config import HOST, PORT

# ═══════════════════════════════════════
# AEROSKY BACKEND v1.0
# Runs behind Nginx reverse proxy
# Binds to 127.0.0.1 — Nginx is public face
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
    "strict-transport-security": (
        "max-age=63072000; includeSubDomains"
    ),
}

STRIP_HEADERS = {
    "x-powered-by", "x-process-time", "via",
    "x-cache", "x-varnish", "cf-ray",
    "content-length",
}


class SecurityMiddleware:
    """
    Pure ASGI security middleware.
    Non-blocking — no response buffering.
    Nginx handles rate limiting + SSL.
    We handle header stripping + security.
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
                for h in STRIP_HEADERS:
                    headers.pop(
                        h.encode(), None)
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
            scope, receive, send_with_headers)


def create_app() -> FastAPI:
    _app = FastAPI(
        title="AeroSky Backend",
        description=(
            "Privacy-focused VPN controller"
        ),
        version="1.0.0",
        docs_url="/docs",
        redoc_url="/redoc",
        # Trust nginx proxy headers
        # So real client IP is available
    )

    _app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    # No-auth endpoints
    _app.include_router(
        health_router, prefix="/api/v1")

    # Authenticated endpoints
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


# Create app then wrap with security
_base_app = create_app()
app = SecurityMiddleware(_base_app)

# ═══════════════════════════════════════
# DIRECT RUN (dev only)
# Production uses systemd + nginx
# ═══════════════════════════════════════

if __name__ == "__main__":
    uvicorn.run(
        "main:app",
        host=HOST,
        port=PORT,
        reload=False,
        workers=1,
        log_level="warning",
        access_log=True,
        # Trust nginx proxy headers
        proxy_headers=True,
        forwarded_allow_ips="127.0.0.1",
    )
