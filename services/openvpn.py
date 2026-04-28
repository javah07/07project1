import subprocess
import os
import asyncio
from typing import Optional
from config import OPENVPN_CONFIG, CLIENTS_DIR


class OpenVpnService:
    """
    Controls OpenVPN server on the VPS.
    OpenVPN is the first layer in the chain:
    Client → OpenVPN → WireGuard → ProtonVPN
    """

    def __init__(self):
        self._process: Optional[
            asyncio.subprocess.Process
        ] = None

    # ═══════════════════════════════════
    # SERVICE CONTROL
    # ═══════════════════════════════════

    async def start(self) -> bool:
        """Start OpenVPN server service"""
        try:
            result = subprocess.run(
                ["systemctl", "start", "openvpn"],
                capture_output=True,
                text=True,
                timeout=30
            )
            return result.returncode == 0
        except Exception as e:
            print(f"OpenVPN start error: {e}")
            return False

    async def stop(self) -> bool:
        """Stop OpenVPN server service"""
        try:
            result = subprocess.run(
                ["systemctl", "stop", "openvpn"],
                capture_output=True,
                text=True,
                timeout=30
            )
            return result.returncode == 0
        except Exception as e:
            print(f"OpenVPN stop error: {e}")
            return False

    async def restart(self) -> bool:
        """Restart OpenVPN server service"""
        try:
            result = subprocess.run(
                ["systemctl", "restart", "openvpn"],
                capture_output=True,
                text=True,
                timeout=30
            )
            return result.returncode == 0
        except Exception as e:
            print(f"OpenVPN restart error: {e}")
            return False

    # ═══════════════════════════════════
    # STATUS
    # ═══════════════════════════════════

    def is_running(self) -> bool:
        """Check if OpenVPN service is active"""
        try:
            result = subprocess.run(
                ["systemctl", "is-active", "openvpn"],
                capture_output=True,
                text=True,
                timeout=5
            )
            return result.stdout.strip() == "active"
        except Exception:
            return False

    def get_connected_clients(self) -> list[dict]:
        """
        Read OpenVPN status file to get
        list of connected clients.
        OpenVPN writes this file automatically.
        """
        clients = []
        status_file = "/var/log/openvpn/status.log"

        try:
            if not os.path.exists(status_file):
                return clients

            with open(status_file, "r") as f:
                lines = f.readlines()

            # Parse the status file format
            in_client_section = False
            for line in lines:
                line = line.strip()

                if line == "CLIENT_LIST":
                    in_client_section = True
                    continue

                if line == "ROUTING_TABLE":
                    in_client_section = False
                    continue

                if in_client_section and line:
                    parts = line.split(",")
                    if len(parts) >= 4:
                        clients.append({
                            "name": parts[0],
                            "real_address": parts[1],
                            "vpn_address": parts[2],
                            "connected_since": parts[4]
                            if len(parts) > 4 else ""
                        })

        except Exception as e:
            print(f"Error reading OpenVPN status: {e}")

        return clients

    # ═══════════════════════════════════
    # CLIENT CONFIG GENERATION
    # ═══════════════════════════════════

    def generate_client_config(
        self,
        client_name: str,
        server_address: str
    ) -> Optional[str]:
        """
        Generate an .ovpn config file
        for a friend to import into
        their OpenVPN client.
        """
        try:
            # Use EasyRSA to generate client cert
            # This assumes EasyRSA is installed
            # at /etc/openvpn/easy-rsa/
            easyrsa_path = "/etc/openvpn/easy-rsa"

            # Generate client certificate
            subprocess.run(
                [
                    f"{easyrsa_path}/easyrsa",
                    "gen-req",
                    client_name,
                    "nopass"
                ],
                capture_output=True,
                cwd=easyrsa_path,
                timeout=30
            )

            subprocess.run(
                [
                    f"{easyrsa_path}/easyrsa",
                    "sign-req",
                    "client",
                    client_name
                ],
                input=b"yes\n",
                capture_output=True,
                cwd=easyrsa_path,
                timeout=30
            )

            # Read certificates
            ca_cert = self._read_file(
                f"{easyrsa_path}/pki/ca.crt"
            )
            client_cert = self._read_file(
                f"{easyrsa_path}/pki/issued/"
                f"{client_name}.crt"
            )
            client_key = self._read_file(
                f"{easyrsa_path}/pki/private/"
                f"{client_name}.key"
            )
            ta_key = self._read_file(
                "/etc/openvpn/ta.key"
            )

            if not all([
                ca_cert,
                client_cert,
                client_key,
                ta_key
            ]):
                return None

            # Build .ovpn config
            config = f"""client
dev tun
proto udp
remote {server_address} 1194
resolv-retry infinite
nobind
persist-key
persist-tun
remote-cert-tls server
auth SHA256
cipher AES-256-GCM
verb 3

<ca>
{ca_cert}
</ca>

<cert>
{client_cert}
</cert>

<key>
{client_key}
</key>

<tls-auth>
{ta_key}
</tls-auth>
key-direction 1
"""
            return config

        except Exception as e:
            print(f"Config generation error: {e}")
            return None

    def _read_file(
        self,
        path: str
    ) -> Optional[str]:
        """Read a file safely"""
        try:
            with open(path, "r") as f:
                return f.read()
        except Exception:
            return None

    def revoke_client(
        self,
        client_name: str
    ) -> bool:
        """Revoke a client's certificate"""
        try:
            easyrsa_path = "/etc/openvpn/easy-rsa"
            result = subprocess.run(
                [
                    f"{easyrsa_path}/easyrsa",
                    "revoke",
                    client_name
                ],
                input=b"yes\n",
                capture_output=True,
                cwd=easyrsa_path,
                timeout=30
            )
            return result.returncode == 0
        except Exception as e:
            print(f"Revoke error: {e}")
            return False
