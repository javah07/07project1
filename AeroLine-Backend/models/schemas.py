from pydantic import BaseModel, computed_field
from pydantic import ConfigDict
from typing import Optional
from enum import Enum


# ═══════════════════════════════════════
# ENUMS
# ═══════════════════════════════════════

class VpnProtocol(str, Enum):
    full_chain     = "FullChain"
    standard       = "Standard"
    openvpn_only   = "OpenVpnOnly"
    wireguard_only = "WireGuardOnly"
    direct         = "Direct"


# ═══════════════════════════════════════
# VPN STATUS
# ═══════════════════════════════════════

class ChainStatus(BaseModel):
    model_config = ConfigDict(
        populate_by_name=True
    )

    open_vpn_active: bool = False
    wire_guard_active: bool = False
    proton_vpn_active: bool = False
    open_vpn_latency_ms: int = 0
    wire_guard_latency_ms: int = 0
    proton_vpn_latency_ms: int = 0

    # Fixed: use computed_field not @property
    @computed_field
    @property
    def total_latency_ms(self) -> int:
        return (
            self.open_vpn_latency_ms +
            self.wire_guard_latency_ms +
            self.proton_vpn_latency_ms
        )


class VpnStatus(BaseModel):
    model_config = ConfigDict(
        populate_by_name=True
    )

    is_connected: bool = False
    active_protocol: VpnProtocol = (
        VpnProtocol.full_chain)
    visible_ip_address: str = "Unknown"
    visible_country: str = "Unknown"
    kill_switch_active: bool = False
    download_speed_mbps: float = 0.0
    upload_speed_mbps: float = 0.0
    bytes_transferred: int = 0
    error_message: str = ""
    chain_status: ChainStatus = (
        ChainStatus())


# ═══════════════════════════════════════
# CONNECTED USER
# ═══════════════════════════════════════

class ConnectedUser(BaseModel):
    model_config = ConfigDict(
        populate_by_name=True)

    display_name: str
    client_id: str
    connected_since: str
    vpn_ip_address: str
    active_protocol: VpnProtocol = (
        VpnProtocol.full_chain)
    download_speed_mbps: float = 0.0
    upload_speed_mbps: float = 0.0
    bytes_transferred: int = 0
    is_active: bool = True
    last_seen: str = ""
    connection_duration_formatted: str = ""


# ═══════════════════════════════════════
# REQUEST BODIES
# ═══════════════════════════════════════

class ConnectRequest(BaseModel):
    protocol: VpnProtocol = (
        VpnProtocol.full_chain)
    kill_switch: bool = True


class ProtocolRequest(BaseModel):
    protocol: VpnProtocol


class KillSwitchRequest(BaseModel):
    enabled: bool


class GenerateClientRequest(BaseModel):
    display_name: str
    protocol: VpnProtocol = (
        VpnProtocol.full_chain)


# ═══════════════════════════════════════
# RESPONSES
# ═══════════════════════════════════════

class SuccessResponse(BaseModel):
    success: bool = True
    message: str = "OK"


class IpResponse(BaseModel):
    ip: str
    country: str = "Unknown"
    city: str = "Unknown"
