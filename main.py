import uvicorn
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from routers.vpn import router as vpn_router, health_router
from routers.users import router as users_router
from routers.network import router as network_router
from routers.auth import router as auth_router
from config import HOST, PORT

# ═══════════════════════════════════════
# AEROSKY BACKEND (Hardened)
# Behind Nginx reverse proxy
# ═══════════════════════════════════════

# Minimal headers (let Nginx handle most security)
SECURITY_HEADERS = {
    b"x-content-type-options": b"nosniff",
    b"x-frame-options": b"DENY",
}

# Headers safe to strip (DO NOT include content-length)
STRIP_HEADERS = {
    b"x-powered-by",
    b"x-process-time",
    b"via",
    b"x-cache",
    b"x-varnish",
    b"cf-ray",
}


class SecurityMiddleware:
    """
    ASGI middleware with correct header handling.
    Does NOT break multi-value headers.
    """

    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        async def send_with_headers(message):
            if message["type"] == "http.response.start":
                original_headers = message.get("headers", [])

                # Filter headers safely (preserve duplicates)
                filtered_headers = [
                    (k, v)
                    for (k, v) in original_headers
                    if k not in STRIP_HEADERS
                ]

                # Append security headers (do not overwrite duplicates blindly)
                filtered_headers.extend(SECURITY_HEADERS.items())

                message = {
                    **message,
                    "headers": filtered_headers,
                }

            await send(message)

        await self.app(scope, receive, send_with_headers)


def create_app() -> FastAPI:
    # Basic config validation
    if not isinstance(PORT, int):
        raise ValueError("PORT must be an integer")

    _app = FastAPI(
        title="AeroSky Backend",
        description="Privacy-focused VPN controller",
        version="1.0.0",

        # Disable docs in production
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
    )

    # CORS (FIXED: no wildcard + credentials)
    _app.add_middleware(
        CORSMiddleware,
        allow_origins=[
            "https://aerosky.duckdns.org"
        ],  # change if needed
        allow_credentials=True,
        allow_methods=["GET", "POST", "PUT", "DELETE"],
        allow_headers=["Authorization", "Content-Type"],
    )

    # Routers
    _app.include_router(health_router, prefix="/api/v1")
    _app.include_router(auth_router, prefix="/api/v1")
    _app.include_router(vpn_router, prefix="/api/v1")
    _app.include_router(users_router, prefix="/api/v1")
    _app.include_router(network_router, prefix="/api/v1")

    @_app.get("/")
    async def root():
        return {"status": "ok"}

    # Global exception handler (prevents leakage)
    @_app.exception_handler(Exception)
    async def global_exception_handler(request: Request, exc: Exception):
        return JSONResponse(
            status_code=500,
            content={"detail": "Internal Server Error"},
        )

    return _app


# Build app
_base_app = create_app()

# Wrap with middleware (optional — can remove if Nginx handles everything)
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

        # Trust only local proxy (nginx)
        proxy_headers=True,
        forwarded_allow_ips="127.0.0.1",
    )
