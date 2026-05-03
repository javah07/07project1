#!/bin/bash

set -euo pipefail
[[ "${DEBUG:-}" == "1" ]] && set -x

# ───────────── CONFIG ─────────────
APP_USER="aerosky"
DEPLOY_DIR="/opt/aerosky"
VENV_DIR="$DEPLOY_DIR/venv"
REP_URL="https://github.com/javah07/07project1.git"
DOMAIN="aerosky.duckdns.org"
EMAIL="admin@$DOMAIN"
DUCK_TOKEN="${DUCKDNS_TOKEN:-}"
DUCK_TOKEN_FILE="/root/.duckdns_token"

export DEBIAN_FRONTEND=noninteractive

# ───────────── ROOT CHECK ─────────────
if [ "$EUID" -ne 0 ]; then
  echo "❌ Run as root (sudo)."
  exit 1
fi

# ───────────── TOKEN INPUT ─────────────
if [ -z "$DUCK_TOKEN" ]; then
    read -p "Enter DuckDNS Token: " DUCK_TOKEN
fi

echo "$DUCK_TOKEN" > "$DUCK_TOKEN_FILE"
chmod 600 "$DUCK_TOKEN_FILE"

echo "🚀 Starting AeroSky Hardened Deployment..."

# ───────────── SYSTEM PREP ─────────────
apt update
apt upgrade -y
apt install -y python3 python3-pip python3-venv wireguard-tools iptables \
    curl git ufw net-tools nginx certbot python3-certbot-nginx cron

# ───────────── USER SETUP ─────────────
if ! id "$APP_USER" &>/dev/null; then
    useradd -r -m -d "$DEPLOY_DIR" -s /usr/sbin/nologin "$APP_USER"
fi

# ───────────── CODE DEPLOY ─────────────
if [ ! -d "$DEPLOY_DIR/.git" ]; then
    git clone "$REP_URL" "$DEPLOY_DIR"
else
    cd "$DEPLOY_DIR"
    git pull --ff-only
fi

# Optional: pin commit (uncomment and set)
# git checkout <commit-hash>

# ───────────── PERMISSIONS ─────────────
mkdir -p /etc/aerosky/keys
chown -R "$APP_USER":"$APP_USER" /etc/aerosky
chmod 700 /etc/aerosky

# ───────────── ENV SETUP ─────────────
ENV_FILE="$DEPLOY_DIR/.env"
if [ ! -f "$ENV_FILE" ]; then
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

# ───────────── PYTHON SETUP ─────────────
echo "🐍 Setting up virtualenv..."
sudo -u "$APP_USER" python3 -m venv "$VENV_DIR"
sudo -u "$APP_USER" "$VENV_DIR/bin/pip" install --upgrade pip
sudo -u "$APP_USER" "$VENV_DIR/bin/pip" install -r "$DEPLOY_DIR/requirements.txt"

# ───────────── DUCKDNS ─────────────
echo "🦆 Configuring DuckDNS..."
DUCK_SCRIPT="/usr/local/bin/duckdns_update.sh"

cat > "$DUCK_SCRIPT" <<'EOF'
#!/bin/bash
TOKEN=$(cat /root/.duckdns_token)
curl -sS "https://www.duckdns.org/update?domains=aerosky.duckdns.org&token=$TOKEN&ip=" \
  -o /var/log/duckdns.log
EOF

chmod 700 "$DUCK_SCRIPT"

(crontab -l 2>/dev/null | grep -Fv "$DUCK_SCRIPT"; echo "*/5 * * * * $DUCK_SCRIPT") | crontab -

bash "$DUCK_SCRIPT"

# ───────────── SYSCTL ─────────────
grep -q "^net.ipv4.ip_forward=1" /etc/sysctl.conf || echo "net.ipv4.ip_forward=1" >> /etc/sysctl.conf
sysctl -w net.ipv4.ip_forward=1

# ───────────── FIREWALL ─────────────
ufw --force reset
ufw default deny incoming
ufw default allow outgoing
ufw allow 22/tcp
ufw allow 51820/udp
ufw allow 80/tcp
ufw allow 443/tcp
ufw --force enable

# ───────────── NGINX ─────────────
if ! grep -q "limit_req_zone" /etc/nginx/nginx.conf; then
    sed -i '/http {/a \    limit_req_zone $binary_remote_addr zone=aerosky:10m rate=20r/s;\n    server_tokens off;' /etc/nginx/nginx.conf
fi

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

# ───────────── SSL ─────────────
certbot --nginx -d "$DOMAIN" --non-interactive --agree-tos -m "$EMAIL" --redirect

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
    }
}
EOF

nginx -t && systemctl reload nginx

# ───────────── SYSTEMD ─────────────
cat > /etc/systemd/system/aerosky.service <<EOF
[Unit]
Description=AeroSky Backend
After=network.target

[Service]
User=$APP_USER
Group=$APP_USER
WorkingDirectory=$DEPLOY_DIR
Environment="PATH=$VENV_DIR/bin"
ExecStart=$VENV_DIR/bin/uvicorn main:app --host 127.0.0.1 --port 8000 --proxy-headers --forwarded-allow-ips='*'

Restart=always
RestartSec=5

NoNewPrivileges=true
ProtectSystem=full
ProtectHome=yes
PrivateTmp=true
ProtectKernelTunables=true
ProtectControlGroups=true
RestrictRealtime=true

ReadWritePaths=$DEPLOY_DIR /etc/aerosky

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable aerosky
systemctl restart aerosky

# ───────────── HEALTH CHECK ─────────────
echo "📡 Checking API..."
for i in {1..10}; do
    STATUS=$(curl -s -o /dev/null -w "%{http_code}" http://127.0.0.1:8000/api/v1/health || true)
    if [ "$STATUS" = "200" ]; then
        echo "✅ LIVE: https://$DOMAIN"
        exit 0
    fi
    sleep 2
done

echo "⚠️ Health check failed. Check logs:"
echo "journalctl -u aerosky -xe"
