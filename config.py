import os
from dotenv import load_dotenv

load_dotenv()

# ═══════════════════════════════════════
# AEROSKY BACKEND CONFIGURATION
# ═══════════════════════════════════════

# API authentication token
API_TOKEN = os.getenv("API_TOKEN", "")

# TOTP secret for authenticator app
TOTP_SECRET = os.getenv("TOTP_SECRET", "")

# Server bind settings
# 127.0.0.1 = only accept from nginx
# Change to 0.0.0.0 for direct access
# (not recommended in production)
HOST = os.getenv("HOST", "127.0.0.1")
PORT = int(os.getenv("PORT", "8000"))

# Public domain
DOMAIN = os.getenv(
    "DOMAIN", "aerosky.duckdns.org")
ISSUER = os.getenv(
    "ISSUER",
    f"https://aerosky.duckdns.org")
AUDIENCE = os.getenv("AUDIENCE", "AeroLine")

# JWT
JWT_EXPIRE_MINUTES = int(
    os.getenv("JWT_EXPIRE_MINUTES", "60"))

# Database
DB_PATH = os.getenv(
    "DB_PATH", "/etc/aerosky/aero.db")

# Key storage
KEY_DIR = os.getenv(
    "KEY_DIR", "/etc/aerosky/keys")

# ProtonVPN settings
PROTON_USERNAME = os.getenv(
    "PROTON_USERNAME", "")
PROTON_PASSWORD = os.getenv(
    "PROTON_PASSWORD", "")
PROTON_SERVER = os.getenv(
    "PROTON_SERVER", "IS")  # Iceland

# WireGuard
WG_INTERFACE = os.getenv(
    "WG_INTERFACE", "wg0")

# OpenVPN
OPENVPN_CONFIG = os.getenv(
    "OPENVPN_CONFIG",
    "/etc/openvpn/server.conf")
CLIENTS_DIR = os.getenv(
    "CLIENTS_DIR",
    "/etc/openvpn/clients")

# Server address for client configs
SERVER_ADDRESS = os.getenv(
    "SERVER_ADDRESS", "aerosky.duckdns.org")

SPEED_SAMPLE_INTERVAL = 1
