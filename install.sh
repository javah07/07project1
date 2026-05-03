#!/bin/bash
set -e
# ───────────── AeroSky Backend Hardened Install ─────────────
# Usage: sudo bash install.sh
# Ubuntu 22.04/24.04 | HTTPS via DuckDNS+Let's Encrypt | Hardened

# 0. VARS
APP_USER="aerosky"
DEPLOY_DIR="/opt/aerosky"
VENV_DIR="$DEPLOY_DIR/venv"
REP_URL="https://github.com/javah07/07project1.git"
SERVICE_FILE="/etc/systemd/system/aerosky.service"
ENV_FILE="$DEPLOY_DIR/.env"
ENV_EXAMPLE="$DEPLOY_DIR/.env.example"
DOMAIN="yourduckdnsdomain.duckdns.org" # set your DuckDNS domain

# 1. SYSTEM PREP
apt update && apt upgrade -y
apt install -y python3 python3-pip python3-venv wireguard-tools iptables curl git ufw net-tools nginx snapd

# 2. USER & CLONE
id "$APP_USER" &>/dev/null || useradd -r -d "$DEPLOY_DIR" -s /usr/sbin/nologin "$APP_USER"
if [ ! -d "$DEPLOY_DIR/.git" ]; then
    rm -rf "$DEPLOY_DIR"
    git clone "$REP_URL" "$DEPLOY_DIR"
fi
cd "$DEPLOY_DIR" && git pull
chown -R "$APP_USER":root "$DEPLOY_DIR"

# 3. PYTHON ENV
[ -d "$VENV_DIR" ] || python3 -m venv "$VENV_DIR"
source "$VENV_DIR/bin/activate"
pip install --upgrade pip
pip install -r requirements.txt

# 4. SECRETS & PERM
[ -f "$ENV_FILE" ] || (cp "$ENV_EXAMPLE" "$ENV_FILE" && echo 'Fill out .env now!')
chmod 600 "$ENV_FILE"; chown "$APP_USER":root "$ENV_FILE"
mkdir -p /etc/aerosky/keys; chmod 700 /etc/aerosky/keys; chown root:root /etc/aerosky/keys

# 5. FIREWALL & SYSCTL
ufw --force reset; ufw default deny incoming; ufw default allow outgoing
ufw allow ssh; ufw allow 51820/udp; ufw allow 'Nginx Full'; ufw --force enable
grep -qxF 'net.ipv4.ip_forward=1' /etc/sysctl.conf || echo 'net.ipv4.ip_forward=1' >> /etc/sysctl.conf
grep -qxF 'net.ipv6.conf.all.forwarding=1' /etc/sysctl.conf || echo 'net.ipv6.conf.all.forwarding=1' >> /etc/sysctl.conf
sysctl -p

# 6. NGINX SSL REVERSE PROXY
cat > /etc/nginx/sites-available/aerosky <<EOF
server {
    listen 443 ssl http2;
    server_name $DOMAIN;
    ssl_certificate /etc/letsencrypt/live/$DOMAIN/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/$DOMAIN/privkey.pem;
    add_header Strict-Transport-Security "max-age=63072000; includeSubDomains" always;
    add_header X-Frame-Options DENY always;
    add_header X-Content-Type-Options nosniff always;
    add_header Referrer-Policy no-referrer;
    add_header Content-Security-Policy "default-src 'self';" always;
    client_max_body_size 8M;
    limit_req_zone $binary_remote_addr zone=aerosky:10m rate=20r/s;
    limit_req   zone=aerosky burst=20;
    location / {
        proxy_pass http://127.0.0.1:8000;
        proxy_set_header Host $http_host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_http_version 1.1;
    }
}
server {
    listen 80;
    server_name $DOMAIN;
    return 301 https://$host$request_uri;
}
EOF
ln -sf /etc/nginx/sites-available/aerosky /etc/nginx/sites-enabled/aerosky
rm -f /etc/nginx/sites-enabled/default || true
echo "[!] Get SSL: snap install --classic certbot && certbot --nginx -d $DOMAIN"
systemctl restart nginx && systemctl enable nginx

# 7. SYSTEMD + HEALTH CHECK
cat > "$SERVICE_FILE" <<EOF
[Unit]
Description=AeroSky Backend (Hardened Uvicorn FastAPI)
After=network.target

[Service]
Type=simple
User=$APP_USER
WorkingDirectory=$DEPLOY_DIR
Environment=PATH=$VENV_DIR/bin
Environment=PYTHONUNBUFFERED=1
ExecStart=$VENV_DIR/bin/uvicorn main:app --host 127.0.0.1 --port 8000 --workers 1 --proxy-headers
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF
systemctl daemon-reload; systemctl enable aerosky; systemctl restart aerosky
for i in {1..12}; do sleep 5; STATUS=$(curl -s -o /dev/null -w "%{http_code}" http://127.0.0.1:8000/api/v1/health || echo "000"); [ "$STATUS" = "200" ] && echo 'API UP' && break; [ "$i" -eq 12 ] && echo 'API DOWN' && exit 1; done
echo 'AeroSky DEPLOYED!'
