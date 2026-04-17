#!/bin/bash
# ═══════════════════════════════════════
# AeroLine VPS Setup Script
# Run this on your fresh Ubuntu VPS
# from 1984.hosting
#
# Usage: sudo bash install.sh
# ═══════════════════════════════════════

set -e  # Stop on any error

echo "════════════════════════════════"
echo "  AeroLine VPS Setup"
echo "════════════════════════════════"

# ═══════════════════════════════════════
# STEP 1 — System Update
# ═══════════════════════════════════════
echo ""
echo "[1/7] Updating system..."
apt update && apt upgrade -y

# ═══════════════════════════════════════
# STEP 2 — Install Dependencies
# ═══════════════════════════════════════
echo ""
echo "[2/7] Installing dependencies..."
apt install -y \
    python3 \
    python3-pip \
    python3-venv \
    openvpn \
    easy-rsa \
    wireguard \
    wireguard-tools \
    iptables \
    curl \
    wget \
    git \
    ufw \
    net-tools

# ═══════════════════════════════════════
# STEP 3 — Install ProtonVPN CLI
# ═══════════════════════════════════════
echo ""
echo "[3/7] Installing ProtonVPN CLI..."
wget -q -O /tmp/protonvpn-stable-release.deb \
    https://repo.protonvpn.com/debian/dists/stable/main/binary-all/protonvpn-stable-release_1.0.3-3_all.deb
dpkg -i /tmp/protonvpn-stable-release.deb
apt update
apt install -y protonvpn-cli

# ═══════════════════════════════════════
# STEP 4 — Setup Python Environment
# ═══════════════════════════════════════
echo ""
echo "[4/7] Setting up Python environment..."
mkdir -p /opt/aeroline
cd /opt/aeroline

python3 -m venv venv
source venv/bin/activate
pip install --upgrade pip
pip install -r /opt/aeroline/requirements.txt

# ═══════════════════════════════════════
# STEP 5 — Configure Firewall
# ═══════════════════════════════════════
echo ""
echo "[5/7] Configuring firewall..."
ufw default deny incoming
ufw default allow outgoing
ufw allow ssh
ufw allow 8000/tcp    # AeroLine API
ufw allow 1194/udp    # OpenVPN
ufw allow 51820/udp   # WireGuard
ufw --force enable

echo "Firewall configured."

# ═══════════════════════════════════════
# STEP 6 — Enable IP Forwarding
# ═══════════════════════════════════════
echo ""
echo "[6/7] Enabling IP forwarding..."
echo "net.ipv4.ip_forward=1" >> /etc/sysctl.conf
echo "net.ipv6.conf.all.forwarding=1" >> /etc/sysctl.conf
sysctl -p

# ═══════════════════════════════════════
# STEP 7 — Create Systemd Service
# ═══════════════════════════════════════
echo ""
echo "[7/7] Creating AeroLine service..."
cat > /etc/systemd/system/aeroline.service << EOF
[Unit]
Description=AeroLine VPN Backend
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=/opt/aeroline
Environment=PATH=/opt/aeroline/venv/bin
ExecStart=/opt/aeroline/venv/bin/python main.py
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable aeroline

echo ""
echo "════════════════════════════════"
echo "  Installation Complete!"
echo "════════════════════════════════"
echo ""
echo "Next steps:"
echo "1. Copy your backend files to /opt/aeroline/"
echo "2. Copy .env.example to /opt/aeroline/.env"
echo "3. Fill in your .env file with:"
echo "   - API_TOKEN (generate with: python3 -c \"import secrets; print(secrets.token_hex(32))\")"
echo "   - TOTP_SECRET"
echo "   - PROTON_USERNAME"
echo "   - PROTON_PASSWORD"
echo "4. Run: systemctl start aeroline"
echo "5. Check: systemctl status aeroline"
echo ""
echo "API will be available at:"
echo "http://YOUR_VPS_IP:8000"
echo "http://YOUR_VPS_IP:8000/docs"
echo ""
