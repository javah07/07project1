#!/bin/bash

set -euo pipefail
[[ "${DEBUG:-}" == "1" ]] && set -x
umask 027

# ───────────── CONFIG ─────────────
APP_USER="aerosky"
DEPLOY_DIR="/opt/aerosky"
VENV_DIR="$DEPLOY_DIR/venv"
REP_URL="https://github.com/javah07/07project1.git"
DOMAIN="aerosky.duckdns.org"
EMAIL="admin@$DOMAIN"
DUCK_TOKEN="${DUCKDNS_TOKEN:-}"
DUCK_TOKEN_FILE="/root/.duckdns_token"
DUCK_SUBDOMAIN="${DOMAIN%%.duckdns.org}"

export DEBIAN_FRONTEND=noninteractive

# ───────────── HELPERS ─────────────
retry() {
  local attempts=3 delay=5
  for ((i=1;i<=attempts;i++)); do
    "$@" && return 0 || {
      echo "⚠️ Attempt $i failed: $*"
      sleep $delay
    }
  done
  echo "❌ Command failed after $attempts attempts: $*"
  exit 1
}

# ───────────── ROOT CHECK ─────────────
[ "$EUID" -eq 0 ] || { echo "Run as root"; exit 1; }

# ───────────── BASIC SANITY ─────────────
echo "🔍 Checking system resources..."
df -h / | awk 'NR==2 {if ($5+0 > 90) {print "Disk almost full"; exit 1}}'
free -m | awk '/Mem:/ {if ($2 < 512) {print "Low memory"; exit 1}}'

# ───────────── TOKEN ─────────────
if [ -z "$DUCK_TOKEN" ]; then
  read -p "Enter DuckDNS Token: " DUCK_TOKEN
fi
echo "$DUCK_TOKEN" > "$DUCK_TOKEN_FILE"
chmod 600 "$DUCK_TOKEN_FILE"

echo "🚀 Starting deployment..."

# ───────────── SYSTEM PREP ─────────────
retry apt update
retry apt upgrade -y
retry apt install -y python3 python3-pip python3-venv \
  curl git ufw nginx certbot python3-certbot-nginx cron

# ───────────── USER ─────────────
if ! id "$APP_USER" &>/dev/null; then
  useradd -r -m -d "$DEPLOY_DIR" -s /usr/sbin/nologin "$APP_USER"
fi

# ───────────── CODE ─────────────
git config --global --add safe.directory "$DEPLOY_DIR" || true

if [ -d "$DEPLOY_DIR/.git" ]; then
  cd "$DEPLOY_DIR"
  retry git fetch --all
  retry git reset --hard origin/main
elif [ -d "$DEPLOY_DIR" ] && [ -n "$(find "$DEPLOY_DIR" -mindepth 1 -maxdepth 1 2>/dev/null)" ]; then
  echo "⚠️ $DEPLOY_DIR exists and is not a git repo."
  echo "   Backing it up and cloning a fresh copy."
  BACKUP_DIR="${DEPLOY_DIR}.bak.$(date +%Y%m%d%H%M%S)"
  mv "$DEPLOY_DIR" "$BACKUP_DIR"
  retry git clone "$REP_URL" "$DEPLOY_DIR"
else
  mkdir -p "$DEPLOY_DIR"
  retry git clone "$REP_URL" "$DEPLOY_DIR"
fi

# OPTIONAL: pin commit
# git checkout <commit>

# Ensure app user can create venv and write runtime files
chown -R "$APP_USER":"$APP_USER" "$DEPLOY_DIR"

# ───────────── PERMS ─────────────
mkdir -p /etc/aerosky/keys
chown -R "$APP_USER":"$APP_USER" /etc/aerosky
chmod 700 /etc/aerosky

# ───────────── ENV ─────────────
ENV_FILE="$DEPLOY_DIR/.env"
if [ ! -f "$ENV_FILE" ]; then
  GEN_API_TOKEN=$(python3 -c "import secrets; print(secrets.token_hex(32))")
  GEN_TOTP=$(python3 -c "import secrets; print(secrets.token_hex(16))")

  TMP_ENV=$(mktemp)
  cat > "$TMP_ENV" <<EOF
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

  mv "$TMP_ENV" "$ENV_FILE"
fi

chown "$APP_USER":"$APP_USER" "$ENV_FILE"
chmod 600 "$ENV_FILE"

# ───────────── PYTHON ─────────────
echo "🐍 Python setup..."
if [ ! -d "$VENV_DIR" ]; then
  sudo -u "$APP_USER" python3 -m venv "$VENV_DIR"
fi

retry sudo -u "$APP_USER" "$VENV_DIR/bin/pip" install --upgrade pip

# REQUIREMENTS SHOULD BE PINNED
retry sudo -u "$APP_USER" "$VENV_DIR/bin/pip" install -r "$DEPLOY_DIR/requirements.txt"

# ───────────── DUCKDNS ─────────────
echo "🦆 DuckDNS setup..."
DUCK_SCRIPT="/usr/local/bin/duckdns_update.sh"

cat > "$DUCK_SCRIPT" <<EOF
#!/bin/bash
TOKEN=\$(cat $DUCK_TOKEN_FILE)
curl -fsS "https://www.duckdns.org/update?domains=$DUCK_SUBDOMAIN&token=\$TOKEN&ip=" -o /var/log/duckdns.log
EOF

chmod 700 "$DUCK_SCRIPT"

(crontab -l 2>/dev/null | grep -Fv "$DUCK_SCRIPT"; echo "*/5 * * * * $DUCK_SCRIPT") | crontab -

if ! bash "$DUCK_SCRIPT"; then
  echo "⚠️ DuckDNS update failed (check token/domain/network)."
  echo "   Continuing deployment; review /var/log/duckdns.log."
fi

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
echo "🌐 Nginx setup..."

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

# Check port 80
if ss -tuln | grep -q ":80 "; then
  echo "Port 80 OK"
else
  echo "❌ Port 80 not open"
  exit 1
fi

# ───────────── SSL ─────────────
retry certbot --nginx -d "$DOMAIN" --non-interactive --agree-tos -m "$EMAIL" --redirect

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

ExecStart=$VENV_DIR/bin/uvicorn main:app --host 127.0.0.1 --port 8000 --proxy-headers --forwarded-allow-ips=127.0.0.1

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

# Verify systemd
systemctl is-active --quiet aerosky || {
  echo "❌ Service failed to start"
  journalctl -u aerosky -xe
  exit 1
}

# ───────────── HEALTH CHECK ─────────────
echo "📡 Health check..."
for i in {1..15}; do
  STATUS=$(curl -s -o /dev/null -w "%{http_code}" http://127.0.0.1:8000/api/v1/health || true)
  [ "$STATUS" = "200" ] && break
  sleep 2
done

if [ "$STATUS" = "200" ]; then
  echo "✅ LIVE: https://$DOMAIN"
else
  echo "⚠️ Health check failed"
  journalctl -u aerosky -xe
  exit 1
fi
