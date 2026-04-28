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
# Ubuntu Server ready
# ═══════════════════════════════════════

SECURITY_HEADERS = {
    "server": "AeroSky",
    "x-content-type-options": "nosniff",
    "x-frame-options": "DENY",
    "referrer-policy": "no-referrer",
    "cache-control": "no-store, no-cache, must-revalidate, private",
    "pragma": "no-cache",
}

STRIP_HEADERS = {
    "x-powered-by", "x-process-time", "via",
    "x-cache", "x-varnish", "cf-ray", "content-length",
}


class SecurityMiddleware:
    """
    Pure ASGI security middleware.
    Non-blocking — no response buffering.
    """

    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        async def send_with_headers(message):
            if message["type"] == "http.response.start":
                headers = dict(message.get("headers", []))
                for h in STRIP_HEADERS:
                    headers.pop(h.encode(), None)
                for k, v in SECURITY_HEADERS.items():
                    headers[k.encode()] = v.encode()
                message = {**message, "headers": list(headers.items())}
            await send(message)

        await self.app(scope, receive, send_with_headers)


# ═══════════════════════════════════════
# APP FACTORY — single FastAPI instance
# ═══════════════════════════════════════

def create_app() -> FastAPI:
    _app = FastAPI(
        title="AeroSky Backend",
        description="Privacy-focused VPN chain controller",
        version="1.0.0",
        docs_url="/docs",
        redoc_url="/redoc"
    )

    _app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )
    _app.add_middleware(SecurityMiddleware)

    # No-auth endpoints first
    _app.include_router(health_router, prefix="/api/v1")

    # Authenticated endpoints
    _app.include_router(auth_router, prefix="/api/v1")
    _app.include_router(vpn_router, prefix="/api/v1")
    _app.include_router(users_router, prefix="/api/v1")
    _app.include_router(network_router, prefix="/api/v1")

    @_app.get("/")
    async def root():
        return {"service": "AeroSky", "status": "running"}

    return _app


app = create_app()

# ═══════════════════════════════════════
# DIRECT RUN
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
