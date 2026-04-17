import os
from dotenv import load_dotenv

load_dotenv()

# ═══════════════════════════════════════
# AEROLINE BACKEND CONFIGURATION
# Copy .env.example to .env and fill in
# ═══════════════════════════════════════

# API authentication token
# Generate with: python -c "import secrets; print(secrets.token_hex(32))"
API_TOKEN = os.getenv("API_TOKEN", "")

# TOTP secret for authenticator app
# Must match what's in AeroLine Windows app
TOTP_SECRET = os.getenv("TOTP_SECRET", "")

# Server bind settings
HOST = os.getenv("HOST", "0.0.0.0")
PORT = int(os.getenv("PORT", "8000"))

# ProtonVPN settings
PROTON_USERNAME = os.getenv("PROTON_USERNAME", "")
PROTON_PASSWORD = os.getenv("PROTON_PASSWORD", "")
PROTON_SERVER = os.getenv("PROTON_SERVER", "IS")  # Iceland by default

# WireGuard interface name
WG_INTERFACE = os.getenv("WG_INTERFACE", "wg0")

# OpenVPN config file path
OPENVPN_CONFIG = os.getenv(
    "OPENVPN_CONFIG",
    "/etc/openvpn/server.conf"
)

# Client configs directory
CLIENTS_DIR = os.getenv(
    "CLIENTS_DIR",
    "/etc/openvpn/clients"
)

# How many seconds between
# speed measurement samples
SPEED_SAMPLE_INTERVAL = 1
