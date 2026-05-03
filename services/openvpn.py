import subprocess
import os
import asyncio
import logging
from typing import Optional
from config import OPENVPN_CONFIG, CLIENTS_DIR
logger = logging.getLogger(__name__)


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
        self._service_name = os.getenv(
            "OPENVPN_SERVICE_NAME", "openvpn"
        )

    @staticmethod
    def _run(
        cmd: list[str],
        timeout: int = 30,
        text: bool = True,
        input_data=None,
        cwd: Optional[str] = None
    ) -> subprocess.CompletedProcess:
        return subprocess.run(
            cmd,
            capture_output=True,
            text=text,
            timeout=timeout,
            input=input_data,
            cwd=cwd
        )

    # ═══════════════════════════════════
    # SERVICE CONTROL
    # ═══════════════════════════════════

    async def start(self) -> bool:
        """Start OpenVPN server service"""
        try:
            result = await asyncio.to_thread(
                subprocess.run,
                ["systemctl", "start", self._service_name],
                ["systemctl", "start", "openvpn"],
                capture_output=True,
                text=True,
                timeout=30
            )
            return result.returncode == 0
        except Exception:
            logger.exception("OpenVPN start error")
            return False

    async def stop(self) -> bool:
        """Stop OpenVPN server service"""
        try:
            result = await asyncio.to_thread(
                subprocess.run,
                ["systemctl", "stop", self._service_name],
                ["systemctl", "stop", "openvpn"],
                capture_output=True,
                text=True,
                timeout=30
            )
            return result.returncode == 0
        except Exception:
            logger.exception("OpenVPN stop error")
            return False

    async def restart(self) -> bool:
        """Restart OpenVPN server service"""
        try:
            result = await asyncio.to_thread(
                subprocess.run,
                ["systemctl", "restart", self._service_name],
                ["systemctl", "restart", "openvpn"],
                capture_output=True,
                text=True,
                timeout=30
            )
            return result.returncode == 0
        except Exception:
            logger.exception("OpenVPN restart error")
            return False

    # ═══════════════════════════════════
    # STATUS
    # ═══════════════════════════════════

    def is_running(self) -> bool:
        """Check if OpenVPN service is active"""
        try:
            result = self._run(
                ["systemctl", "is-active", self._service_name],
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

        except Exception:
            logger.exception("Error reading OpenVPN status")

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
            self._run(
                [
                    f"{easyrsa_path}/easyrsa",
                    "gen-req",
                    client_name,
                    "nopass"
                ],
                cwd=easyrsa_path,
                timeout=30
            )

            self._run(
                [
                    f"{easyrsa_path}/easyrsa",
                    "sign-req",
                    "client",
                    client_name
                ],
                input_data=b"yes\n",
                text=False,
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

        except Exception:
            logger.exception("Config generation error")
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
            result = self._run(
                [
                    f"{easyrsa_path}/easyrsa",
                    "revoke",
                    client_name
                ],
                input_data=b"yes\n",
                text=False,
                cwd=easyrsa_path,
                timeout=30
            )
            return result.returncode == 0
        except Exception:
            logger.exception("Revoke error")
            return False
