#!/bin/bash
# ═══════════════════════════════════════
# AeroSky Backend Setup Script
# For Ubuntu Server 22.04+ on RPi 4
# or any amd64/arm64 VPS
#
# Usage: sudo bash install.sh
# ═══════════════════════════════════════

set -e

echo "════════════════════════════════"
echo "  AeroSky Backend Setup"
echo "════════════════════════════════"

# ═══════════════════════════════════════
# STEP 1 — System Update
# ═══════════════════════════════════════
echo ""
echo "[1/8] Updating system..."
apt update && apt upgrade -y

# ═══════════════════════════════════════
# STEP 2 — Install Core Dependencies
# ═══════════════════════════════════════
echo ""
echo "[2/8] Installing dependencies..."
apt install -y \
    python3 \
    python3-pip \
    python3-venv \
    wireguard-tools \
    iptables \
    curl \
    wget \
    git \
    ufw \
    net-tools

# ═══════════════════════════════════════
# STEP 3 — Clone / Deploy Backend
# ═══════════════════════════════════════
echo ""
echo "[3/8] Deploying AeroSky backend..."
DEPLOY_DIR="/opt/aerosky"

if [ -d "$DEPLOY_DIR" ]; then
    echo "  Backend already exists at $DEPLOY_DIR"
    echo "  Pulling latest changes..."
    cd "$DEPLOY_DIR" && git pull
else
    echo "  Cloning repo..."
    mkdir -p "$DEPLOY_DIR"
    # Replace with your actual repo URL
    # git clone https://github.com/YOUR_USERNAME/AeroLine-Backend.git "$DEPLOY_DIR"
    echo "  NOTE: Clone your repo manually into $DEPLOY_DIR"
    echo "  Then re-run this script, or copy files manually."
fi

# ═══════════════════════════════════════
# STEP 4 — Python Environment
# ═══════════════════════════════════════
echo ""
echo "[4/8] Setting up Python environment..."
cd "$DEPLOY_DIR"
python3 -m venv venv
source venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt

# ═══════════════════════════════════════
# STEP 5 — Environment Variables
# ═══════════════════════════════════════
echo ""
echo "[5/8] Configuring environment..."
if [ ! -f "$DEPLOY_DIR/.env" ]; then
    cp "$DEPLOY_DIR/.env.example" "$DEPLOY_DIR/.env"
    echo "  Created .env from template — fill it in before starting!"
    echo "  Edit: nano $DEPLOY_DIR/.env"
else
    echo "  .env already exists"
fi

mkdir -p /etc/aerosky/keys
chmod 700 /etc/aerosky/keys

# ═══════════════════════════════════════
# STEP 6 — Firewall
# ═══════════════════════════════════════
echo ""
echo "[6/8] Configuring firewall..."
ufw default deny incoming
ufw default allow outgoing
ufw allow ssh
ufw allow 8000/tcp    # AeroSky API
ufw allow 51820/udp    # WireGuard
ufw --force enable
echo "  Firewall configured."

# ═══════════════════════════════════════
# STEP 7 — IP Forwarding
# ═══════════════════════════════════════
echo ""
echo "[7/8] Enabling IP forwarding..."
echo "net.ipv4.ip_forward=1" >> /etc/sysctl.conf
echo "net.ipv6.conf.all.forwarding=1" >> /etc/sysctl.conf
sysctl -p
echo "  IP forwarding enabled."

# ═══════════════════════════════════════
# STEP 8 — Systemd Service
# ═══════════════════════════════════════
echo ""
echo "[8/8] Creating systemd service..."
cat > /etc/systemd/system/aerosky.service << EOF
[Unit]
Description=AeroSky VPN Backend
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=${DEPLOY_DIR}
Environment=PATH=${DEPLOY_DIR}/venv/bin
Environment=PYTHONUNBUFFERED=1
ExecStart=${DEPLOY_DIR}/venv/bin/python -m uvicorn main:app --host 0.0.0.0 --port 8000 --workers 1
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable aerosky

echo ""
echo "════════════════════════════════"
echo "  Installation Complete!"
echo "════════════════════════════════"
echo ""
echo "Next steps:"
echo "1. Edit .env: nano $DEPLOY_DIR/.env"
echo "   - Set ISSUER to your server's public IP or domain"
echo "   - Set DB_PATH to '$DEPLOY_DIR/aero.db'"
echo ""
echo "2. Add your WireGuard config:"
echo "   sudo cp your-wg.conf /etc/wireguard/wg0.conf"
echo "   sudo wg-quick up wg0"
echo ""
echo "3. Start the backend:"
echo "   sudo systemctl start aerosky"
echo "   sudo systemctl status aerosky"
echo ""
echo "4. Check logs:"
echo "   journalctl -u aerosky -f"
echo ""
echo "API available at: http://YOUR_IP:8000"
echo "Docs at:          http://YOUR_IP:8000/docs"
echo ""
