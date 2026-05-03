from datetime import datetime
from fastapi import APIRouter, Depends, HTTPException
from models.schemas import (
    ConnectedUser,
    VpnProtocol,
    GenerateClientRequest,
    SuccessResponse
)
from services.openvpn import OpenVpnService
from services.wireguard import WireGuardService
from auth.middleware import verify_token
import os

router = APIRouter(
    prefix="/users",
    tags=["User Management"],
    dependencies=[Depends(verify_token)]
)

openvpn = OpenVpnService()
wireguard = WireGuardService()

# ═══════════════════════════════════════
# GET CONNECTED USERS
# ═══════════════════════════════════════

@router.get(
    "/connected",
    response_model=list[ConnectedUser]
)
async def get_connected_users():
    """
    Get list of friends currently
    connected to AeroLine VPN.
    Combines OpenVPN and WireGuard clients.
    """
    users = []

    # Get OpenVPN clients
    ovpn_clients = openvpn.get_connected_clients()
    for client in ovpn_clients:
        connected_since = client.get(
            "connected_since", ""
        )
        users.append(ConnectedUser(
            display_name=client.get("name", "Unknown"),
            client_id=f"ovpn_{client.get('name', '')}",
            connected_since=connected_since,
            vpn_ip_address=client.get(
                "vpn_address", ""
            ),
            active_protocol=VpnProtocol.full_chain,
            is_active=True,
            last_seen=datetime.now().isoformat(),
            connection_duration_formatted=(
                _format_duration(connected_since)
            )
        ))

    # Get WireGuard peers
    wg_status = wireguard.get_status()
    for peer in wg_status.get("peers", []):
        # Only show recently active peers
        # (handshake within last 3 minutes)
        last_handshake = peer.get(
            "latest_handshake", ""
        )
        if last_handshake and "minute" in (
            last_handshake.lower()
        ):
            users.append(ConnectedUser(
                display_name=f"WG Peer",
                client_id=f"wg_{peer.get('public_key', '')[:8]}",
                connected_since=(
                    datetime.now().isoformat()
                ),
                vpn_ip_address=peer.get(
                    "allowed_ips", ""
                ).split("/")[0],
                active_protocol=(
                    VpnProtocol.wireguard_only
                ),
                is_active=True,
                last_seen=(
                    datetime.now().isoformat()
                ),
                connection_duration_formatted=(
                    last_handshake
                )
            ))

    return users

# ═══════════════════════════════════════
# GENERATE CLIENT CONFIG
# ═══════════════════════════════════════

@router.post("/generate")
async def generate_client_config(
    request: GenerateClientRequest
):
    """
    Generate a VPN config file for a friend.
    Returns the .ovpn file content as text.
    They import this into their VPN client.
    """
    # Get server's public address
    server_address = os.getenv(
        "SERVER_ADDRESS", "aerosky.duckdns.org"
    )

    config = openvpn.generate_client_config(
        client_name=request.display_name
        .replace(" ", "_")
        .lower(),
        server_address=server_address
    )

    if not config:
        raise HTTPException(
            status_code=500,
            detail="Failed to generate config. "
                   "Check OpenVPN/EasyRSA setup."
        )

    return config

# ═══════════════════════════════════════
# REVOKE CLIENT
# ═══════════════════════════════════════

@router.delete(
    "/{client_id}",
    response_model=SuccessResponse
)
async def revoke_client(client_id: str):
    """
    Revoke a friend's VPN access.
    Works for both OpenVPN and WireGuard clients.
    """
    if client_id.startswith("ovpn_"):
        client_name = client_id.replace(
            "ovpn_", ""
        )
        success = openvpn.revoke_client(
            client_name
        )
    elif client_id.startswith("wg_"):
        # For WireGuard, need public key
        # This is simplified — in production
        # you'd store key→name mappings
        success = False
    else:
        success = False

    return SuccessResponse(
        success=success,
        message="Access revoked" if success
        else "Revocation failed"
    )

# ═══════════════════════════════════════
# HELPERS
# ═══════════════════════════════════════
def _format_duration(
    connected_since: str
) -> str:
    """Format connection duration as Xh Ym"""
    try:
        # Try to parse OpenVPN timestamp format
        start = datetime.strptime(
            connected_since,
            "%a %b %d %H:%M:%S %Y"
        )
        duration = datetime.now() - start
        hours = int(duration.total_seconds() // 3600)
        minutes = int(
            (duration.total_seconds() % 3600) // 60
        )
        return f"{hours}h {minutes}m"
    except Exception:
        return "0h 0m"
