import subprocess
import re
from typing import Optional
from config import WG_INTERFACE


class WireGuardService:
    """
    Controls WireGuard on the VPS.
    WireGuard is the second layer in the chain:
    Client → OpenVPN → WireGuard → ProtonVPN

    WireGuard also handles client-to-client
    routing for the friend group.
    """

    # ═══════════════════════════════════
    # SERVICE CONTROL
    # ═══════════════════════════════════

    async def start(self) -> bool:
        """Bring up WireGuard interface"""
        try:
            result = subprocess.run(
                ["wg-quick", "up", WG_INTERFACE],
                capture_output=True,
                text=True,
                timeout=30
            )
            return result.returncode == 0
        except Exception as e:
            print(f"WireGuard start error: {e}")
            return False

    async def stop(self) -> bool:
        """Bring down WireGuard interface"""
        try:
            result = subprocess.run(
                ["wg-quick", "down", WG_INTERFACE],
                capture_output=True,
                text=True,
                timeout=30
            )
            return result.returncode == 0
        except Exception as e:
            print(f"WireGuard stop error: {e}")
            return False

    # ═══════════════════════════════════
    # STATUS
    # ═══════════════════════════════════

    def is_running(self) -> bool:
        """Check if WireGuard interface is up"""
        try:
            result = subprocess.run(
                ["wg", "show", WG_INTERFACE],
                capture_output=True,
                text=True,
                timeout=5
            )
            return result.returncode == 0
        except Exception:
            return False

    def get_status(self) -> dict:
        """
        Get full WireGuard status including
        connected peers (your 4 friends)
        """
        try:
            result = subprocess.run(
                ["wg", "show", WG_INTERFACE],
                capture_output=True,
                text=True,
                timeout=5
            )

            if result.returncode != 0:
                return {"running": False, "peers": []}

            output = result.stdout
            peers = self._parse_peers(output)

            return {
                "running": True,
                "interface": WG_INTERFACE,
                "peers": peers
            }
        except Exception as e:
            print(f"WireGuard status error: {e}")
            return {"running": False, "peers": []}

    def _parse_peers(
        self,
        wg_output: str
    ) -> list[dict]:
        """Parse wg show output into peer list"""
        peers = []
        current_peer = None

        for line in wg_output.split("\n"):
            line = line.strip()

            if line.startswith("peer:"):
                if current_peer:
                    peers.append(current_peer)
                current_peer = {
                    "public_key": line
                    .replace("peer:", "")
                    .strip(),
                    "endpoint": "",
                    "allowed_ips": "",
                    "latest_handshake": "",
                    "transfer_rx": 0,
                    "transfer_tx": 0
                }

            elif current_peer:
                if line.startswith("endpoint:"):
                    current_peer["endpoint"] = (
                        line.replace("endpoint:", "")
                        .strip()
                    )
                elif line.startswith("allowed ips:"):
                    current_peer["allowed_ips"] = (
                        line.replace("allowed ips:", "")
                        .strip()
                    )
                elif line.startswith(
                    "latest handshake:"
                ):
                    current_peer[
                        "latest_handshake"
                    ] = (
                        line.replace(
                            "latest handshake:", ""
                        ).strip()
                    )
                elif line.startswith("transfer:"):
                    transfer = line.replace(
                        "transfer:", ""
                    ).strip()
                    # Parse "X received, Y sent"
                    match = re.search(
                        r"([\d.]+\s+\w+) received,"
                        r"\s+([\d.]+\s+\w+) sent",
                        transfer
                    )
                    if match:
                        current_peer[
                            "transfer_rx"
                        ] = match.group(1)
                        current_peer[
                            "transfer_tx"
                        ] = match.group(2)

        if current_peer:
            peers.append(current_peer)

        return peers

    # ═══════════════════════════════════
    # PEER MANAGEMENT
    # ═══════════════════════════════════

    def add_peer(
        self,
        public_key: str,
        allowed_ips: str,
        endpoint: Optional[str] = None
    ) -> bool:
        """Add a new friend as a WireGuard peer"""
        try:
            cmd = [
                "wg", "set", WG_INTERFACE,
                "peer", public_key,
                "allowed-ips", allowed_ips
            ]

            if endpoint:
                cmd.extend(["endpoint", endpoint])

            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=10
            )

            if result.returncode == 0:
                # Save to config permanently
                subprocess.run(
                    ["wg-quick", "save",
                     WG_INTERFACE],
                    capture_output=True,
                    timeout=10
                )

            return result.returncode == 0

        except Exception as e:
            print(f"Add peer error: {e}")
            return False

    def remove_peer(
        self,
        public_key: str
    ) -> bool:
        """Remove a friend's WireGuard peer"""
        try:
            result = subprocess.run(
                [
                    "wg", "set", WG_INTERFACE,
                    "peer", public_key, "remove"
                ],
                capture_output=True,
                text=True,
                timeout=10
            )

            if result.returncode == 0:
                subprocess.run(
                    ["wg-quick", "save",
                     WG_INTERFACE],
                    capture_output=True,
                    timeout=10
                )

            return result.returncode == 0

        except Exception as e:
            print(f"Remove peer error: {e}")
            return False

    def generate_keypair(self) -> dict:
        """
        Generate a new WireGuard keypair
        for a new friend's client config
        """
        try:
            # Generate private key
            private = subprocess.run(
                ["wg", "genkey"],
                capture_output=True,
                text=True,
                timeout=5
            )
            private_key = private.stdout.strip()

            # Derive public key
            public = subprocess.run(
                ["wg", "pubkey"],
                input=private_key,
                capture_output=True,
                text=True,
                timeout=5
            )
            public_key = public.stdout.strip()

            return {
                "private_key": private_key,
                "public_key": public_key
            }

        except Exception as e:
            print(f"Keypair generation error: {e}")
            return {}
