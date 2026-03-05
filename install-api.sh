#!/bin/bash
# ─────────────────────────────────────────────────────────────────
#   NEXUSDEV — API Installer (HTTPS via Nginx, tanpa port)
#   Akses: https://domain.com/api/...
# ─────────────────────────────────────────────────────────────────

Green="\e[92;1m"; RED="\033[1;31m"; YELLOW="\033[33m"
BLUE="\033[36m"; FONT="\033[0m"; NC='\e[0m'
OK="${Green}--->${FONT}"; ERROR="${RED}[ERROR]${FONT}"

print_ok()    { echo -e "${OK} ${BLUE} $1 ${FONT}"; }
print_error() { echo -e "${ERROR} ${RED} $1 ${FONT}"; }
print_head()  {
  echo -e "\033[96;1m┌─────────────────────────────────────────────────┐\033[0m"
  echo -e "\033[96;1m│  $1\033[0m"
  echo -e "\033[96;1m└─────────────────────────────────────────────────┘\033[0m"
  echo ""
}

clear
print_head "⚡ NEXUSDEV — API INSTALLER (HTTPS MODE)"

[[ $EUID -ne 0 ]] && { print_error "Run as root!"; exit 1; }

DOMAIN=$(cat /etc/xray/domain 2>/dev/null || echo "")
if [[ -z "$DOMAIN" ]]; then
  print_error "Domain tidak ditemukan di /etc/xray/domain"
  exit 1
fi
print_ok "Domain: $DOMAIN"

# ── 1. Install Node.js ───────────────────────────────────────────────────────
if ! command -v node &>/dev/null; then
  print_ok "Installing Node.js v18..."
  curl -fsSL https://deb.nodesource.com/setup_18.x | bash - >/dev/null 2>&1
  apt-get install -y nodejs >/dev/null 2>&1
fi
print_ok "Node.js: $(node -v)"

# ── 2. Create API dir & copy api.js ─────────────────────────────────────────
mkdir -p /etc/xray/api
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

if [[ -f "$SCRIPT_DIR/api.js" ]]; then
  cp "$SCRIPT_DIR/api.js" /etc/xray/api/api.js
  print_ok "api.js disalin dari lokal"
else
  print_ok "Mendownload api.js..."
  wget -q -O /etc/xray/api/api.js \
    "https://raw.githubusercontent.com/AutoNV/gh/main/api/api.js" 2>/dev/null
fi

# ── 3. Generate / tampilkan AUTH key ────────────────────────────────────────
if [[ ! -f /etc/ssh/api_auth.key ]] || [[ -z "$(cat /etc/ssh/api_auth.key 2>/dev/null)" ]]; then
  NEW_KEY=$(tr -dc 'a-z0-9' < /dev/urandom | head -c 12)
  echo "$NEW_KEY" > /etc/ssh/api_auth.key
  chmod 600 /etc/ssh/api_auth.key
  print_ok "API Key baru dibuat: $NEW_KEY"
else
  print_ok "API Key ada: $(cat /etc/ssh/api_auth.key)"
fi

AUTH_KEY=$(cat /etc/ssh/api_auth.key)

# ── 4. Install systemd service ───────────────────────────────────────────────
cat > /etc/systemd/system/xray-api.service <<'EOF'
[Unit]
Description=NEXUSDEV REST API Service
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=/etc/xray/api
ExecStart=/usr/bin/node /etc/xray/api/api.js
Restart=on-failure
RestartSec=5
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF

print_ok "Systemd service ditulis"

# ── 5. Patch Nginx — tambahkan location /api/ ────────────────────────────────
NGINX_CONF="/etc/nginx/conf.d/xray.conf"

if [[ ! -f "$NGINX_CONF" ]]; then
  print_error "File nginx tidak ditemukan: $NGINX_CONF"
  print_error "Coba cari manual dan tambahkan block location /api/ secara manual"
else
  # Cek apakah sudah ada
  if grep -q "location /api/" "$NGINX_CONF" 2>/dev/null; then
    print_ok "Nginx location /api/ sudah ada, skip patch"
  else
    # Backup dulu
    cp "$NGINX_CONF" "${NGINX_CONF}.bak.$(date +%s)"
    print_ok "Backup nginx disimpan"

    # Sisipkan sebelum baris penutup server block (baris 'server_name' terakhir / '}' terakhir)
    # Cari posisi closing brace terakhir dan sisipkan sebelumnya
    LOCATION_BLOCK='
    # ── REST API proxy (NEXUSDEV) ───────────────────────
    location /api/ {
        proxy_pass         http://127.0.0.1:7979;
        proxy_http_version 1.1;
        proxy_set_header   Host              $host;
        proxy_set_header   X-Real-IP         $remote_addr;
        proxy_set_header   X-Forwarded-For   $proxy_add_x_forwarded_for;
        proxy_set_header   X-Forwarded-Proto $scheme;
        proxy_read_timeout 30s;
        proxy_connect_timeout 10s;
        add_header Access-Control-Allow-Origin  "*" always;
        add_header Access-Control-Allow-Methods "GET, POST, OPTIONS" always;
        add_header Access-Control-Allow-Headers "Authorization, Content-Type" always;
        if ($request_method = OPTIONS) { return 204; }
    }
    # ──────────────────────────────────────────────────────────'

    # Tambah sebelum baris } terakhir di server block HTTPS (443)
    # Cari baris "listen 443" lalu sisipkan location sebelum } penutupnya
    python3 - <<PYEOF
import re, sys

with open("$NGINX_CONF", "r") as f:
    content = f.read()

location_block = """
    # ── REST API proxy (NEXUSDEV) ───────────────────────
    location /api/ {
        proxy_pass         http://127.0.0.1:7979;
        proxy_http_version 1.1;
        proxy_set_header   Host              \$host;
        proxy_set_header   X-Real-IP         \$remote_addr;
        proxy_set_header   X-Forwarded-For   \$proxy_add_x_forwarded_for;
        proxy_set_header   X-Forwarded-Proto \$scheme;
        proxy_read_timeout 30s;
        proxy_connect_timeout 10s;
        add_header Access-Control-Allow-Origin  "*" always;
        add_header Access-Control-Allow-Methods "GET, POST, OPTIONS" always;
        add_header Access-Control-Allow-Headers "Authorization, Content-Type" always;
        if (\$request_method = OPTIONS) { return 204; }
    }
    # ──────────────────────────────────────────────────────────
"""

# Find the last closing brace and insert before it
last_brace = content.rfind("}")
if last_brace == -1:
    print("ERROR: Could not find closing brace")
    sys.exit(1)

new_content = content[:last_brace] + location_block + "\n" + content[last_brace:]

with open("$NGINX_CONF", "w") as f:
    f.write(new_content)

print("OK: location /api/ inserted")
PYEOF

    if [[ $? -eq 0 ]]; then
      print_ok "Location /api/ ditambahkan ke nginx.conf"
    else
      print_error "Gagal patch otomatis. Tambahkan manual:"
      echo ""
      echo "  Buka: $NGINX_CONF"
      echo "  Tambahkan sebelum } terakhir di server block 443:"
      cat "$SCRIPT_DIR/nginx-api.conf" 2>/dev/null || echo "  (lihat file nginx-api.conf)"
      echo ""
    fi
  fi

  # Test nginx config
  if nginx -t 2>/dev/null; then
    print_ok "Nginx config valid"
  else
    print_error "Nginx config INVALID — restoring backup"
    BACKUP=$(ls -t ${NGINX_CONF}.bak.* 2>/dev/null | head -1)
    [[ -n "$BACKUP" ]] && cp "$BACKUP" "$NGINX_CONF"
  fi
fi

# ── 6. Start services ────────────────────────────────────────────────────────
systemctl daemon-reload
systemctl enable xray-api.service >/dev/null 2>&1
systemctl stop  xray-api.service >/dev/null 2>&1
systemctl start xray-api.service
sleep 1

nginx -t >/dev/null 2>&1 && systemctl reload nginx
print_ok "Nginx reloaded"

# ── 7. Status ────────────────────────────────────────────────────────────────
clear
echo ""
if systemctl is-active --quiet xray-api.service; then
  API_STATUS="\033[92;1m● RUNNING\033[0m"
else
  API_STATUS="\033[91;1m✘ FAILED\033[0m"
fi

echo -e "\033[96;1m┌─────────────────────────────────────────────────┐\033[0m"
echo -e "\033[96;1m│\033[0m  \033[92;1m✔ INSTALL COMPLETE\033[0m"
echo -e "\033[96;1m│\033[0m  API Status : $API_STATUS"
echo -e "\033[96;1m│\033[0m  Auth Key   : \033[93m${AUTH_KEY}\033[0m"
echo -e "\033[96;1m│\033[0m  API Docs   : \033[96mhttps://${DOMAIN}/api/doc.html\033[0m"
echo -e "\033[96;1m└─────────────────────────────────────────────────┘\033[0m"
echo ""
echo -e " \033[33mEndpoint HTTPS (tanpa port):\033[0m"
echo -e "   https://${DOMAIN}/api/trial-ssh?auth=${AUTH_KEY}"
echo -e "   https://${DOMAIN}/api/create-ssh?auth=${AUTH_KEY}&user=u&password=p&exp=30"
echo -e "   https://${DOMAIN}/api/trial-vmess?auth=${AUTH_KEY}"
echo -e "   https://${DOMAIN}/api/create-vmess?auth=${AUTH_KEY}&user=u&quota=10&limitip=1&exp=30"
echo -e "   https://${DOMAIN}/api/trial-vless?auth=${AUTH_KEY}"
echo -e "   https://${DOMAIN}/api/create-vless?auth=${AUTH_KEY}&user=u&quota=10&limitip=1&exp=30"
echo -e "   https://${DOMAIN}/api/trial-trojan?auth=${AUTH_KEY}"
echo -e "   https://${DOMAIN}/api/create-trojan?auth=${AUTH_KEY}&user=u&quota=10&limitip=1&exp=30"
echo ""
echo -e " \033[33mInstall ulang (1 command):\033[0m"
echo -e " \033[96mwget -q -O install-api.sh https://raw.githubusercontent.com/AutoNV/gh/main/api/install-api.sh && bash install-api.sh\033[0m"
echo ""
read -n 1 -s -r -p " Tekan sembarang tombol untuk kembali..."
echo ""
