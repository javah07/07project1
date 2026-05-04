#!/bin/bash
set -euo pipefail
[[ "${DEBUG:-}" == "1" ]] && set -x
umask 027

APP_USER="aerosky"
DEPLOY_DIR="/opt/aerosky"
VENV_DIR="$DEPLOY_DIR/venv"
REP_URL="https://github.com/javah07/07project1.git"
DOMAIN="aerosky.duckdns.org"
EMAIL="admin@$DOMAIN"
DUCK_TOKEN="${DUCKDNS_TOKEN:-}"
DUCK_TOKEN_FILE="/root/.duckdns_token"
DUCK_SUBDOMAIN="${DOMAIN%%.duckdns.org}"
HEALTH_PATH="${HEALTH_PATH:-/api/v1/health}"

export DEBIAN_FRONTEND=noninteractive

retry() {
  local attempts=3 delay=5
  for ((i=1;i<=attempts;i++)); do
    "$@" && return 0 || sleep $delay
  done
  echo "Command failed: $*"
  exit 1
}

[ "$EUID" -eq 0 ] || { echo "Run as root"; exit 1; }

# ───── SYSTEM CHECKS ─────
df -h / | awk 'NR==2 {if ($5+0 > 90) exit 1}'
free -m | awk '/Mem:/ {if ($2 < 512) exit 1}'

# ───── TOKEN ─────
if [ -z "$DUCK_TOKEN" ]; then
  read -r -p "DuckDNS Token: " DUCK_TOKEN
fi
echo "$DUCK_TOKEN" > "$DUCK_TOKEN_FILE"
chmod 600 "$DUCK_TOKEN_FILE"

# ───── PACKAGES ─────
retry apt update
retry apt install -y \
  python3 python3-pip python3-venv \
  build-essential python3-dev \
  ca-certificates iproute2 \
  curl git ufw nginx certbot cron

systemctl enable --now cron

# ───── SYSCTL (PERSISTENT) ─────
echo "net.ipv4.ip_forward=1" > /etc/sysctl.d/99-aerosky-forwarding.conf
sysctl --system

# ───── FIREWALL (SAFE ORDER) ─────
ufw allow 22/tcp || true
ufw allow 51820/udp || true
ufw allow 80/tcp || true
ufw allow 443/tcp || true
ufw --force enable

# ───── USER ─────
id "$APP_USER" &>/dev/null || useradd -r -m -d "$DEPLOY_DIR" -s /usr/sbin/nologin "$APP_USER"

# ───── CODE ─────
if [ -d "$DEPLOY_DIR/.git" ]; then
  cd "$DEPLOY_DIR"
  retry git fetch --all
  DEFAULT_BRANCH=$(git symbolic-ref refs/remotes/origin/HEAD | sed 's@^refs/remotes/origin/@@')
  retry git reset --hard "origin/$DEFAULT_BRANCH"
else
  rm -rf "$DEPLOY_DIR"
  retry git clone "$REP_URL" "$DEPLOY_DIR"
fi

chown -R "$APP_USER":"$APP_USER" "$DEPLOY_DIR"

# ───── APP DIRS ─────
mkdir -p /etc/aerosky/keys
chown -R "$APP_USER":"$APP_USER" /etc/aerosky
chmod 700 /etc/aerosky

# ───── ENV ─────
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
EOF
fi

chmod 600 "$ENV_FILE"
chown "$APP_USER":"$APP_USER" "$ENV_FILE"

# ───── PYTHON ─────
if [ ! -d "$VENV_DIR" ]; then
  sudo -u "$APP_USER" -H python3 -m venv "$VENV_DIR"
fi

sudo -u "$APP_USER" -H "$VENV_DIR/bin/pip" install --upgrade pip setuptools wheel
sudo -u "$APP_USER" -H "$VENV_DIR/bin/pip" install -r "$DEPLOY_DIR/requirements.txt"

# ───── DUCKDNS ─────
DUCK_SCRIPT="/usr/local/bin/duckdns_update.sh"
cat > "$DUCK_SCRIPT" <<EOF
#!/bin/bash
TOKEN=\$(cat $DUCK_TOKEN_FILE)
curl -fsS --data "domains=$DUCK_SUBDOMAIN&token=\$TOKEN&ip=" \
https://www.duckdns.org/update >> /var/log/duckdns.log 2>&1
EOF
chmod 700 "$DUCK_SCRIPT"

(crontab -l 2>/dev/null | grep -v duckdns_update.sh; echo "*/5 * * * * $DUCK_SCRIPT") | crontab -
bash "$DUCK_SCRIPT" || true

# ───── WAIT FOR DNS PROPAGATION ─────
echo "Waiting for DNS to resolve..."
for i in {1..30}; do
  if getent hosts "$DOMAIN" >/dev/null; then break; fi
  sleep 2
done

# ───── NGINX (HTTP ONLY FIRST) ─────
rm -f /etc/nginx/sites-enabled/default

mkdir -p /var/www/certbot

cat > /etc/nginx/conf.d/aerosky.conf <<EOF
limit_req_zone \$binary_remote_addr zone=aerosky:10m rate=20r/s;

server {
  listen 80;
  server_name $DOMAIN;

  location /.well-known/acme-challenge/ {
    root /var/www/certbot;
  }

  location / {
    proxy_pass http://127.0.0.1:8000;
    proxy_set_header Host \$host;
    proxy_set_header X-Real-IP \$remote_addr;
  }
}
EOF

nginx -t && systemctl restart nginx

# ───── SSL (WEBROOT — SAFE RENEWALS) ─────
retry certbot certonly --webroot \
  -w /var/www/certbot \
  -d "$DOMAIN" \
  --non-interactive --agree-tos -m "$EMAIL"

# verify cert exists
[ -f "/etc/letsencrypt/live/$DOMAIN/fullchain.pem" ] || exit 1

# ───── NGINX SSL ─────
cat > /etc/nginx/conf.d/aerosky_ssl.conf <<EOF
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

server {
  listen 80;
  server_name $DOMAIN;
  return 301 https://\$host\$request_uri;
}
EOF

nginx -t && systemctl reload nginx

# ───── SYSTEMD ─────
cat > /etc/systemd/system/aerosky.service <<EOF
[Unit]
Description=AeroSky Backend
After=network-online.target nginx.service
Wants=network-online.target

[Service]
User=$APP_USER
Group=$APP_USER
WorkingDirectory=$DEPLOY_DIR
EnvironmentFile=$ENV_FILE
Environment="PATH=$VENV_DIR/bin"

ExecStartPre=/bin/sleep 2
ExecStart=$VENV_DIR/bin/uvicorn main:app --host 127.0.0.1 --port 8000 --proxy-headers --forwarded-allow-ips=127.0.0.1

Restart=always
RestartSec=5

NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=true
ProtectKernelTunables=true
ProtectControlGroups=true
RestrictRealtime=true

ReadWritePaths=$DEPLOY_DIR /etc/aerosky /tmp /run

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable aerosky
systemctl restart aerosky

systemctl is-active --quiet aerosky || {
  journalctl -u aerosky -xe
  exit 1
}

# ───── HEALTH CHECK ─────
for i in {1..15}; do
  STATUS=$(curl -s -o /dev/null -w "%{http_code}" "http://127.0.0.1:8000$HEALTH_PATH" || true)
  [ "$STATUS" = "200" ] && break
  sleep 2
done

[ "$STATUS" = "200" ] || {
  journalctl -u aerosky -xe
  exit 1
}

echo "DEPLOYMENT SUCCESSFUL: https://$DOMAIN"
