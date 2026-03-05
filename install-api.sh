#!/bin/bash
# ─────────────────────────────────────────────
#   ARISCTUNNEL V4 - API Service Installer
#   Install / Update REST API (Port 7979)
# ─────────────────────────────────────────────

Green="\e[92;1m"
RED="\033[1;31m"
YELLOW="\033[33m"
BLUE="\033[36m"
FONT="\033[0m"
OK="${Green}--->${FONT}"
ERROR="${RED}[ERROR]${FONT}"

print_ok() { echo -e "${OK} ${BLUE} $1 ${FONT}"; }
print_error() { echo -e "${ERROR} ${RED} $1 ${FONT}"; }

clear
echo -e "\033[96;1m┌─────────────────────────────────────────────────┐\033[0m"
echo -e "\033[96;1m│     ⚡ ARISCTUNNEL V4 - API INSTALLER/UPDATER    │\033[0m"
echo -e "\033[96;1m└─────────────────────────────────────────────────┘\033[0m"
echo ""

# ── Check root ──────────────────────────────────────────────────────────────
if [[ $EUID -ne 0 ]]; then
  print_error "Run as root!"
  exit 1
fi

# ── Install Node.js if missing ───────────────────────────────────────────────
if ! command -v node &>/dev/null; then
  print_ok "Installing Node.js v18..."
  curl -fsSL https://deb.nodesource.com/setup_18.x | bash - >/dev/null 2>&1
  apt-get install -y nodejs >/dev/null 2>&1
  print_ok "Node.js installed: $(node -v)"
else
  print_ok "Node.js found: $(node -v)"
fi

# ── Create API directory ─────────────────────────────────────────────────────
mkdir -p /etc/xray/api
print_ok "API directory ready: /etc/xray/api"

# ── Generate AUTH key if not exists ─────────────────────────────────────────
if [[ ! -f /etc/ssh/api_auth.key ]] || [[ -z "$(cat /etc/ssh/api_auth.key 2>/dev/null)" ]]; then
  NEW_KEY=$(tr -dc 'a-z0-9' < /dev/urandom | head -c 12)
  echo "$NEW_KEY" > /etc/ssh/api_auth.key
  chmod 600 /etc/ssh/api_auth.key
  print_ok "Generated new API Key: $NEW_KEY"
else
  print_ok "API Key exists: $(cat /etc/ssh/api_auth.key)"
fi

# ── Copy API server file ─────────────────────────────────────────────────────
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

if [[ -f "$SCRIPT_DIR/api.js" ]]; then
  cp "$SCRIPT_DIR/api.js" /etc/xray/api/api.js
  print_ok "Copied api.js from local"
else
  # Download from GitHub (update this URL if you host it)
  print_ok "Downloading api.js..."
  wget -q -O /etc/xray/api/api.js \
    "https://raw.githubusercontent.com/AutoNV/gh/main/api/api.js" 2>/dev/null || \
  curl -s -o /etc/xray/api/api.js \
    "https://raw.githubusercontent.com/AutoNV/gh/main/api/api.js" 2>/dev/null
fi

chmod +x /etc/xray/api/api.js

# ── Install systemd service ──────────────────────────────────────────────────
cat > /etc/systemd/system/xray-api.service <<'EOF'
[Unit]
Description=ARISCTUNNEL V4 REST API Service
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

# ── Open firewall port ───────────────────────────────────────────────────────
iptables -I INPUT -p tcp --dport 7979 -j ACCEPT 2>/dev/null
netfilter-persistent save >/dev/null 2>&1

# ── Enable and start service ─────────────────────────────────────────────────
systemctl daemon-reload
systemctl enable xray-api.service >/dev/null 2>&1
systemctl stop xray-api.service >/dev/null 2>&1
systemctl start xray-api.service
sleep 1

# ── Status check ─────────────────────────────────────────────────────────────
DOMAIN=$(cat /etc/xray/domain 2>/dev/null || echo "yourdomain.com")
AUTH_KEY=$(cat /etc/ssh/api_auth.key 2>/dev/null)

if systemctl is-active --quiet xray-api.service; then
  STATUS="\033[92;1mRUNNING\033[0m"
else
  STATUS="\033[91;1mFAILED\033[0m"
fi

echo ""
echo -e "\033[96;1m┌─────────────────────────────────────────────────┐\033[0m"
echo -e "\033[96;1m│\033[0m  \033[92;1m✔ INSTALL/UPDATE COMPLETE\033[0m"
echo -e "\033[96;1m│\033[0m  Status   : $STATUS"
echo -e "\033[96;1m│\033[0m  Port     : \033[93m7979\033[0m"
echo -e "\033[96;1m│\033[0m  Auth Key : \033[93m${AUTH_KEY}\033[0m"
echo -e "\033[96;1m│\033[0m  API Docs : \033[96mhttp://${DOMAIN}:7979/api/doc.html\033[0m"
echo -e "\033[96;1m└─────────────────────────────────────────────────┘\033[0m"
echo ""
echo -e " \033[33mEndpoints available:\033[0m"
echo -e "   GET /api/trial-ssh    — Trial SSH account"
echo -e "   GET /api/create-ssh   — Create SSH account"
echo -e "   GET /api/trial-vmess  — Trial VMess account"
echo -e "   GET /api/create-vmess — Create VMess account"
echo -e "   GET /api/trial-vless  — Trial VLess account"
echo -e "   GET /api/create-vless — Create VLess account"
echo -e "   GET /api/trial-trojan — Trial Trojan account"
echo -e "   GET /api/create-trojan— Create Trojan account"
echo ""
read -n 1 -s -r -p " Press any key to continue..."
echo ""
