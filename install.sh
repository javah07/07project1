#!/bin/bash

# Exit on error, undefined vars, or pipe failures
set -euo pipefail

# ───────────── AeroSky Pro Installer (Hardened) ─────────────
# Usage: sudo DUCKDNS_TOKEN="your-token" bash install.sh
# ────────────────────────────────────────────────────────────

# 0. CONFIGURATION
APP_USER="aerosky"
DEPLOY_DIR="/opt/aerosky"
VENV_DIR="$DEPLOY_DIR/venv"
REP_URL="https://github.com/javah07/07project1.git"
DOMAIN="aerosky.duckdns.org"
EMAIL="admin@$DOMAIN"
# Allow token to be passed via ENV or prompt
DUCK_TOKEN="${DUCKDNS_TOKEN:-}"

export DEBIAN_FRONTEND=noninteractive

if [ -z "$DUCK_TOKEN" ]; then
    read -p "Enter DuckDNS Token: " DUCK_TOKEN
fi

echo "🚀 Starting AeroSky Hardened Deployment..."

# 1. SYSTEM PREP
apt update && apt upgrade -y
apt install -y python3 python3-pip python3-venv wireguard-tools iptables \
    curl git ufw net-tools nginx certbot python3-certbot-nginx sed cron

# 2. USER & DIR SETUP
if ! id "$APP_USER" &>/dev/null; then
    useradd -r -m -d "$DEPLOY_DIR" -s /usr/sbin/nologin "$APP_USER"
fi

# Clone/Pull
if [ ! -d "$DEPLOY_DIR/.git" ]; then
    git clone "$REP_URL" "$DEPLOY_DIR"
else
    cd "$DEPLOY_DIR" && git pull
fi

# 3. PERMISSIONS & DIRECTORIES
mkdir -p /etc/aerosky/keys
# The app needs to write to the DB and use keys
chown -R "$APP_USER":"$APP_USER" /etc/aerosky
chmod 700 /etc/aerosky

# 4. GENERATE .ENV AUTOMATICALLY
echo "📝 Configuring Environment Variables..."
ENV_FILE="$DEPLOY_DIR/.env"
if [ ! -f "$ENV_FILE" ]; then
    # Generate secrets
    GEN_API_TOKEN=$(python3 -c "import secrets; print(secrets.token_hex(32))")
    GEN_TOTP=$(python3 -c "import secrets; print(secrets.token_hex(16))")

    cat > "$ENV_FILE" <<EOF
HOST=127.0.0.1
PORT=8000
DOMAIN=$DOMAIN
SERVER_ADDRESS=$DOMAIN
ISSUER=https://$DOMAIN
AUDIENCE=AeroSky
JWT_ALGORITHM=RS256
JWT_EXPIRE_MINUTES=60
API_TOKEN=$GEN_API_TOKEN
TOTP_SECRET=$GEN_TOTP
DB_PATH=/etc/aerosky/aero.db
KEY_DIR=/etc/aerosky/keys
WG_INTERFACE=wg0
OPENVPN_CONFIG=/etc/openvpn/server.conf
CLIENTS_DIR=/etc/openvpn/clients
EOF
fi
chown "$APP_USER":"$APP_USER" "$ENV_FILE"
chmod 600 "$ENV_FILE"

# 5. PYTHON VENV
echo "🐍 Building Virtual Environment..."
[ -d "$VENV_DIR" ] || sudo -u "$APP_USER" python3 -m venv "$VENV_DIR"
sudo -u "$APP_USER" "$VENV_DIR/bin/pip" install --upgrade pip
sudo -u "$APP_USER" "$VENV_DIR/bin/pip" install -r "$DEPLOY_DIR/requirements.txt"

# 6. DUCKDNS AUTO-UPDATE CRON
echo "🦆 Setting up DuckDNS update task..."
DUCK_SCRIPT="/usr/local/bin/duckdns_update.sh"
cat > "$DUCK_SCRIPT" <<EOF
#!/bin/bash
echo url="https://www.duckdns.org/update?domains=$DOMAIN&token=$DUCK_TOKEN&ip=" | curl -k -o /var/log/duckdns.log -K -
EOF
chmod +x "$DUCK_SCRIPT"
(crontab -l 2>/dev/null | grep -v "duckdns_update.sh"; echo "*/5 * * * * $DUCK_SCRIPT") | crontab -
# Run once now
bash "$DUCK_SCRIPT"

# 7. NETWORKING & FIREWALL
sed -i 's/#net.ipv4.ip_forward=1/net.ipv4.ip_forward=1/' /etc/sysctl.conf
sysctl -p
ufw --force reset
ufw default deny incoming
ufw default allow outgoing
ufw allow ssh
ufw allow 51820/udp
ufw allow 'Nginx Full'
echo "y" | ufw enable

# 8. NGINX SSL BOOTSTRAP
if ! grep -q "limit_req_zone" /etc/nginx/nginx.conf; then
    sed -i '/http {/a \    limit_req_zone $binary_remote_addr zone=aerosky:10m rate=20r/s;\n    server_tokens off;' /etc/nginx/nginx.conf
fi

# Stage 1: Port 80 for Certbot
cat > /etc/nginx/sites-available/aerosky <<EOF
server {
    listen 80;
    server_name $DOMAIN;
    location /.well-known/acme-challenge/ { root /var/www/html; }
    location / { return 301 https://\$host\$request_uri; }
}
EOF
ln -sf /etc/nginx/sites-available/aerosky /etc/nginx/sites-enabled/aerosky
rm -f /etc/nginx/sites-enabled/default
systemctl restart nginx

# Stage 2: SSL
certbot --nginx -d "$DOMAIN" --non-interactive --agree-tos -m "$EMAIL" --redirect

# Stage 3: Full Hardened Proxy
cat > /etc/nginx/sites-available/aerosky <<EOF
server {
    listen 443 ssl http2;
    server_name $DOMAIN;
    ssl_certificate /etc/letsencrypt/live/$DOMAIN/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/$DOMAIN/privkey.pem;

    add_header Strict-Transport-Security "max-age=63072000; includeSubDomains" always;
    add_header X-Frame-Options "DENY" always;
    add_header X-Content-Type-Options "nosniff" always;
    
    limit_req zone=aerosky burst=20 nodelay;

    location / {
        proxy_pass http://127.0.0.1:8000;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
        proxy_http_version 1.1;
    }
}
EOF
nginx -t && systemctl reload nginx

# 9. SYSTEMD SERVICE
cat > /etc/systemd/system/aerosky.service <<EOF
[Unit]
Description=AeroSky Backend
After=network.target

[Service]
Type=simple
User=$APP_USER
Group=$APP_USER
WorkingDirectory=$DEPLOY_DIR
Environment="PATH=$VENV_DIR/bin"
Environment="PYTHONUNBUFFERED=1"
ExecStart=$VENV_DIR/bin/uvicorn main:app --host 127.0.0.1 --port 8000 --proxy-headers --forwarded-allow-ips='*'
Restart=always
RestartSec=5

# Sandboxing
NoNewPrivileges=true
ProtectSystem=full
ProtectHome=yes
PrivateTmp=true
ReadOnlyPaths=/etc /usr
ReadWritePaths=$DEPLOY_DIR /etc/aerosky

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable aerosky
systemctl restart aerosky

# 10. FINAL CHECK
echo "📡 Verifying API..."
sleep 5
STATUS=$(curl -s -o /dev/null -w "%{http_code}" http://127.0.0.1:8000/api/v1/health || echo "FAIL")
if [ "$STATUS" = "200" ]; then
    echo "✅ AeroSky is LIVE at https://$DOMAIN"
else
    echo "⚠️  App started but health check failed ($STATUS). Check: journalctl -u aerosky"
fi
