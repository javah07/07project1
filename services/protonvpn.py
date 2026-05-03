import subprocess
import asyncio
import logging
from typing import Optional
from config import (
    PROTON_USERNAME,
    PROTON_PASSWORD,
    PROTON_SERVER
)
logger = logging.getLogger(__name__)


class ProtonVpnService:
    """
    Controls ProtonVPN CLI on the VPS.
    ProtonVPN is the exit layer in the chain:
    Client → OpenVPN → WireGuard → ProtonVPN → Internet

    All traffic exits through ProtonVPN's
    Iceland or Switzerland servers,
    making the visible IP a ProtonVPN IP.
    """

    # ═══════════════════════════════════
    # CONNECTION CONTROL
    # ═══════════════════════════════════

    async def connect(
        self,
        server: Optional[str] = None
    ) -> bool:
        """
        Connect to ProtonVPN.
        Uses Iceland by default (outside
        Five Eyes and 14 Eyes).
        """
        target = server or PROTON_SERVER

        try:
            # Login first if not already logged in
            if not self.is_logged_in():
                await self._login()

            # Connect to specified server/country
            result = await asyncio.to_thread(
                self._run,
                subprocess.run,
                [
                    "protonvpn-cli",
                    "connect",
                    "--cc", target,  # country code
                    "--protocol", "udp"
                ],
                capture_output=True,
                text=True,
                timeout=60
            )

            return result.returncode == 0

        except Exception:
            logger.exception("ProtonVPN connect error")
            return False

    async def disconnect(self) -> bool:
        """Disconnect from ProtonVPN"""
        try:
            result = await asyncio.to_thread(
                self._run,
                subprocess.run,
                ["protonvpn-cli", "disconnect"],
                timeout=30
            )
            return result.returncode == 0
        except Exception:
            logger.exception("ProtonVPN disconnect error")
            return False

    async def reconnect(self) -> bool:
        """Reconnect to last ProtonVPN server"""
        try:
            result = await asyncio.to_thread(
                self._run,
                subprocess.run,
                ["protonvpn-cli", "reconnect"],
                timeout=60
            )
            return result.returncode == 0
        except Exception:
            logger.exception("ProtonVPN reconnect error")
            return False

    # ═══════════════════════════════════
    # STATUS
    # ═══════════════════════════════════

    def is_connected(self) -> bool:
        """Check if ProtonVPN is connected"""
        try:
            result = self._run(["protonvpn-cli", "status"], timeout=10)
            output = result.stdout.lower()
            return "connected" in output
        except Exception:
            return False

    def is_logged_in(self) -> bool:
        """Check if ProtonVPN CLI is logged in"""
        try:
            result = self._run(["protonvpn-cli", "status"], timeout=10)
            # If not logged in, output contains error
            return "not logged in" not in (
                result.stdout.lower() +
                result.stderr.lower()
            )
        except Exception:
            return False

    def get_current_ip(self) -> Optional[str]:
        """Get current IP from ProtonVPN status"""
        try:
            result = self._run(["protonvpn-cli", "status"], timeout=10)

            for line in result.stdout.split("\n"):
                if "ip" in line.lower():
                    parts = line.split(":")
                    if len(parts) > 1:
                        return parts[1].strip()

            return None

        except Exception:
            return None

    def get_server_info(self) -> dict:
        """Get current ProtonVPN server details"""
        try:
            result = self._run(["protonvpn-cli", "status"], timeout=10)

            info = {
                "connected": False,
                "server": "",
                "country": "",
                "ip": "",
                "protocol": ""
            }

            for line in result.stdout.split("\n"):
                line_lower = line.lower()
                if "connected" in line_lower:
                    info["connected"] = True
                elif "server" in line_lower:
                    parts = line.split(":")
                    if len(parts) > 1:
                        info["server"] = (
                            parts[1].strip()
                        )
                elif "country" in line_lower:
                    parts = line.split(":")
                    if len(parts) > 1:
                        info["country"] = (
                            parts[1].strip()
                        )
                elif "ip" in line_lower:
                    parts = line.split(":")
                    if len(parts) > 1:
                        info["ip"] = (
                            parts[1].strip()
                        )
                elif "protocol" in line_lower:
                    parts = line.split(":")
                    if len(parts) > 1:
                        info["protocol"] = (
                            parts[1].strip()
                        )

            return info

        except Exception:
            logger.exception("ProtonVPN status error")
            return {"connected": False}

    # ═══════════════════════════════════
    # AUTHENTICATION
    # ═══════════════════════════════════

    async def _login(self) -> bool:
        """Login to ProtonVPN CLI"""
        try:
            process = await asyncio.create_subprocess_exec(
                "protonvpn-cli", "login",
                PROTON_USERNAME,
                stdin=asyncio.subprocess.PIPE,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )

            # Send password
            stdout, stderr = await asyncio.wait_for(
                process.communicate(
                    input=f"{PROTON_PASSWORD}\n"
                    .encode()
                ),
                timeout=30
            )

            return process.returncode == 0

        except Exception:
            logger.exception("ProtonVPN login error")
            return False
    @staticmethod
    def _run(
        cmd: list[str],
        timeout: int = 30,
        text: bool = True,
        input_data=None
    ) -> subprocess.CompletedProcess:
        return subprocess.run(
            cmd,
            capture_output=True,
            text=text,
            timeout=timeout,
            input=input_data
        )
