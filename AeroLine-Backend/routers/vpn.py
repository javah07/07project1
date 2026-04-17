import asyncio
import psutil
import httpx
import time
import base64
import struct
import os
from datetime import datetime, timedelta
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ec import (
    ECDH, generate_private_key,
    SECP384R1, BrainpoolP256R1
)
from cryptography.hazmat.primitives.serialization import (
    Encoding, PublicFormat, load_der_public_key
)
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel
from typing import Optional
from models.schemas import (
    VpnStatus, ChainStatus, VpnProtocol,
    ConnectRequest, ProtocolRequest,
    KillSwitchRequest, SuccessResponse
)
from services.openvpn import OpenVpnService
from services.wireguard import WireGuardService
from services.protonvpn import ProtonVpnService
from auth.middleware import verify_token

router = APIRouter(
    prefix="/vpn",
    tags=["VPN Control"],
    dependencies=[Depends(verify_token)]
)

openvpn = OpenVpnService()
wireguard = WireGuardService()
protonvpn = ProtonVpnService()

_current_protocol = VpnProtocol.full_chain
_kill_switch_enabled = True
_connection_start: datetime | None = None
_last_bytes_sent = 0
_last_bytes_recv = 0
_last_speed_check = datetime.now()

# ═══════════════════════════════════════
# SESSION STORE
# ═══════════════════════════════════════
_sessions: dict = {}
_rate_limit: dict = {}
_RATE_LIMIT_WINDOW = 60
_RATE_LIMIT_MAX = 5

def _check_rate_limit(ip: str) -> bool:
    now = time.time()
    if ip not in _rate_limit:
        _rate_limit[ip] = []
    _rate_limit[ip] = [
        t for t in _rate_limit[ip]
        if now - t < _RATE_LIMIT_WINDOW
    ]
    if len(_rate_limit[ip]) >= _RATE_LIMIT_MAX:
        return False
    _rate_limit[ip].append(now)
    return True

def _store_session(sid: str, key: bytes):
    _sessions[sid] = {
        "composite_key": key,
        "created": datetime.now()
    }

def _get_session(sid: str) -> bytes | None:
    s = _sessions.get(sid)
    if not s:
        return None
    if datetime.now() - s["created"] > \
            timedelta(hours=24):
        _clear_session(sid)
        return None
    return s["composite_key"]

def _clear_session(sid: str):
    if sid in _sessions:
        k = _sessions[sid]["composite_key"]
        _sessions[sid]["composite_key"] = \
            bytes(len(k))
        del _sessions[sid]

# ═══════════════════════════════════════
# HEALTH + CANARY (no auth)
# ═══════════════════════════════════════

health_router = APIRouter(tags=["Health"])

@health_router.get("/health")
async def health_check():
    return {
        "status": "online",
        "service": "AeroSky Backend",
        "timestamp": datetime.now().isoformat()
    }

@health_router.get("/canary")
async def warrant_canary():
    return {
        "statement": (
            "AeroSky has received no warrants, "
            "gag orders, or government requests."
        ),
        "date": datetime.now().strftime(
            "%Y-%m-%d"),
        "status": "canary alive"
    }

# ═══════════════════════════════════════
# KEY EXCHANGE — Pydantic model
# Fixes 422 by using typed request body
# ═══════════════════════════════════════

class KeyExchangeRequest(BaseModel):
    publicKey: str
    sessionId: Optional[str] = None

@router.post("/keyexchange")
async def key_exchange(
    body: KeyExchangeRequest,
    request: Request
):
    client_ip = (request.client.host
        if request.client else "unknown")

    if not _check_rate_limit(client_ip):
        raise HTTPException(
            status_code=429,
            detail="Too many requests")

    try:
        sid = body.sessionId or \
            os.urandom(32).hex()

        client_bundle = base64.b64decode(
            body.publicKey)

        curve1_len = struct.unpack_from(
            '<I', client_bundle, 0)[0]
        curve1_pk = client_bundle[
            4:4 + curve1_len]
        curve2_pk = client_bundle[
            4 + curve1_len:]

        # BrainpoolP256R1
        srv_bp = generate_private_key(
            BrainpoolP256R1(), default_backend())
        srv_bp_pub = srv_bp.public_key() \
            .public_bytes(
                Encoding.DER,
                PublicFormat.SubjectPublicKeyInfo)
        cli_bp = load_der_public_key(
            curve1_pk, backend=default_backend())
        s1 = srv_bp.exchange(ECDH(), cli_bp)

        # SECP384R1
        srv_p384 = generate_private_key(
            SECP384R1(), default_backend())
        srv_p384_pub = srv_p384.public_key() \
            .public_bytes(
                Encoding.DER,
                PublicFormat.SubjectPublicKeyInfo)
        cli_p384 = load_der_public_key(
            curve2_pk, backend=default_backend())
        s2 = srv_p384.exchange(ECDH(), cli_p384)

        combined = s1 + s2
        try:
            key = HKDF(
                algorithm=hashes.SHA512(),
                length=64, salt=None,
                info=b"AeroSky-Hybrid-KEM-v1",
                backend=default_backend()
            ).derive(combined)
        finally:
            combined = bytes(len(combined))

        _store_session(sid, key)

        resp_bundle = (
            struct.pack('<I', len(srv_bp_pub)) +
            srv_bp_pub +
            srv_p384_pub
        )

        return {
            "publicKey": base64.b64encode(
                resp_bundle).decode(),
            "success": True,
            "sessionId": sid
        }

    except HTTPException:
        raise
    except Exception:
        raise HTTPException(
            status_code=400,
            detail="Key exchange failed")

# ═══════════════════════════════════════
# VPN STATUS
# ═══════════════════════════════════════

@router.get("/status", response_model=VpnStatus)
async def get_status():
    global _last_bytes_sent, _last_bytes_recv
    global _last_speed_check

    ovpn = openvpn.is_running()
    wg = wireguard.is_running()
    proton = protonvpn.is_connected()
    connected = ovpn or wg

    visible_ip = "Not connected"
    visible_country = "Unknown"

    if proton:
        info = protonvpn.get_server_info()
        visible_ip = info.get("ip", "Unknown")
        visible_country = info.get(
            "country", "Iceland")
    elif connected:
        visible_ip = await _get_public_ip()

    dl, ul = _calculate_speeds()

    chain = ChainStatus(
        open_vpn_active=ovpn,
        wire_guard_active=wg,
        proton_vpn_active=proton,
        open_vpn_latency_ms=(
            await _ping_latency("10.8.0.1")
            if ovpn else 0),
        wire_guard_latency_ms=(
            await _ping_latency("10.0.0.1")
            if wg else 0),
        proton_vpn_latency_ms=(
            await _ping_latency("8.8.8.8")
            if proton else 0)
    )

    return VpnStatus(
        is_connected=connected,
        active_protocol=_current_protocol,
        visible_ip_address=visible_ip,
        visible_country=visible_country,
        kill_switch_active=_kill_switch_enabled,
        download_speed_mbps=dl,
        upload_speed_mbps=ul,
        chain_status=chain
    )

# ═══════════════════════════════════════
# CONNECT
# ═══════════════════════════════════════

@router.post("/connect",
             response_model=SuccessResponse)
async def connect(req: ConnectRequest):
    global _current_protocol
    global _kill_switch_enabled
    global _connection_start

    _current_protocol = req.protocol
    _kill_switch_enabled = req.kill_switch
    success = False

    if req.protocol == VpnProtocol.full_chain:
        ok1 = await openvpn.start()
        await asyncio.sleep(2)
        ok2 = await wireguard.start()
        await asyncio.sleep(1)
        ok3 = await protonvpn.connect()
        success = ok1 and ok2 and ok3
    elif req.protocol == VpnProtocol.standard:
        ok1 = await openvpn.start()
        await asyncio.sleep(2)
        ok2 = await wireguard.start()
        success = ok1 and ok2
    elif req.protocol == VpnProtocol.openvpn_only:
        success = await openvpn.start()
    elif req.protocol == VpnProtocol.wireguard_only:
        success = await wireguard.start()
    elif req.protocol == VpnProtocol.direct:
        await openvpn.stop()
        await wireguard.stop()
        await protonvpn.disconnect()
        success = True

    if success:
        _connection_start = datetime.now()

    return SuccessResponse(
        success=success,
        message="Connected" if success
        else "Connection failed")

# ═══════════════════════════════════════
# DISCONNECT
# ═══════════════════════════════════════

@router.post("/disconnect",
             response_model=SuccessResponse)
async def disconnect():
    global _connection_start

    for sid in list(_sessions.keys()):
        _clear_session(sid)

    await protonvpn.disconnect()
    await asyncio.sleep(1)
    await wireguard.stop()
    await asyncio.sleep(1)
    await openvpn.stop()
    _connection_start = None

    return SuccessResponse(
        success=True,
        message="Disconnected")

# ═══════════════════════════════════════
# SWITCH PROTOCOL
# ═══════════════════════════════════════

@router.post("/protocol",
             response_model=SuccessResponse)
async def switch_protocol(req: ProtocolRequest):
    await disconnect()
    await asyncio.sleep(2)
    return await connect(ConnectRequest(
        protocol=req.protocol,
        kill_switch=_kill_switch_enabled))

# ═══════════════════════════════════════
# KILL SWITCH
# ═══════════════════════════════════════

@router.post("/killswitch",
             response_model=SuccessResponse)
async def set_kill_switch(req: KillSwitchRequest):
    global _kill_switch_enabled
    _kill_switch_enabled = req.enabled

    if req.enabled:
        _enable_kill_switch()
    else:
        _disable_kill_switch()

    return SuccessResponse(
        success=True,
        message=(
            f"Kill switch "
            f"{'enabled' if req.enabled else 'disabled'}"
        ))

# ═══════════════════════════════════════
# HELPERS
# ═══════════════════════════════════════

async def _get_public_ip() -> str:
    try:
        async with httpx.AsyncClient(
                timeout=5) as c:
            r = await c.get(
                "https://api.ipify.org")
            return r.text.strip()
    except Exception:
        return "Unknown"


async def _ping_latency(host: str) -> int:
    try:
        proc = await asyncio \
            .create_subprocess_exec(
            "ping", "-c", "1", "-W", "1", host,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE)
        stdout, _ = await asyncio.wait_for(
            proc.communicate(), timeout=3)
        import re
        m = re.search(
            r"time=([\d.]+)", stdout.decode())
        return int(float(m.group(1))) if m else 0
    except Exception:
        return 0


def _calculate_speeds() -> tuple[float, float]:
    global _last_bytes_sent, _last_bytes_recv
    global _last_speed_check
    try:
        c = psutil.net_io_counters()
        now = datetime.now()
        elapsed = (
            now - _last_speed_check
        ).total_seconds()
        if elapsed < 0.1:
            return 0.0, 0.0
        dl = (c.bytes_recv -
              _last_bytes_recv) / elapsed
        ul = (c.bytes_sent -
              _last_bytes_sent) / elapsed
        _last_bytes_recv = c.bytes_recv
        _last_bytes_sent = c.bytes_sent
        _last_speed_check = now
        return (
            round(max(0, dl * 8 / 1_000_000), 2),
            round(max(0, ul * 8 / 1_000_000), 2))
    except Exception:
        return 0.0, 0.0


def _enable_kill_switch():
    import subprocess
    rules = [
        ["iptables", "-A", "OUTPUT",
         "-o", "lo", "-j", "ACCEPT"],
        ["iptables", "-A", "OUTPUT", "-m",
         "state", "--state",
         "ESTABLISHED,RELATED", "-j", "ACCEPT"],
        ["iptables", "-A", "OUTPUT", "-p",
         "udp", "--dport", "1194",
         "-j", "ACCEPT"],
        ["iptables", "-A", "OUTPUT", "-p",
         "udp", "--dport", "51820",
         "-j", "ACCEPT"],
        ["iptables", "-A", "OUTPUT",
         "-o", "tun0", "-j", "ACCEPT"],
        ["iptables", "-A", "OUTPUT",
         "-o", "wg0", "-j", "ACCEPT"],
        ["iptables", "-A", "OUTPUT",
         "-j", "DROP"],
    ]
    for r in rules:
        try:
            __import__('subprocess').run(
                r, capture_output=True, timeout=5)
        except Exception:
            pass


def _disable_kill_switch():
    try:
        __import__('subprocess').run(
            ["iptables", "-F", "OUTPUT"],
            capture_output=True, timeout=5)
    except Exception:
        pass
