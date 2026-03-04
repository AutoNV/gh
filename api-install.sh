#!/bin/bash
# =========================================
#  ARISCTUNNEL V4 - API INSTALLER/UPDATER
#  Support: SSH, VMess, VLess, Trojan
#  By: ARI VPN STORE
# =========================================

Green="\e[92;1m"
RED="\033[1;31m"
YELLOW="\033[33m"
BLUE="\033[36m"
NC="\e[0m"

API_DIR="/var/www/html/api"
REPO="https://raw.githubusercontent.com/AutoNV/gh/main/api"

function print_banner() {
    clear
    echo -e "\033[96;1m┌─────────────────────────────────────────────────┐\033[0m"
    echo -e "\033[96;1m│       .::.  ARISCTUNNEL V4 API SETUP  .::.      │\033[0m"
    echo -e "\033[96;1m└─────────────────────────────────────────────────┘\033[0m"
    echo ""
}

function print_ok() {
    echo -e "${Green}[✔] $1${NC}"
}

function print_info() {
    echo -e "${BLUE}[•] $1${NC}"
}

function print_error() {
    echo -e "${RED}[✘] $1${NC}"
}

print_banner

# Check root
if [[ $EUID -ne 0 ]]; then
    print_error "Harap jalankan sebagai root!"
    exit 1
fi

print_info "Mengecek dependensi..."

# Install PHP if not available
if ! command -v php &>/dev/null; then
    print_info "Menginstall PHP..."
    apt-get install -y php php-fpm php-cli 2>/dev/null
    print_ok "PHP terinstall"
else
    print_ok "PHP sudah tersedia ($(php -r 'echo PHP_VERSION;'))"
fi

# Install php-fpm if not running
PHP_VER=$(php -r 'echo PHP_MAJOR_VERSION . "." . PHP_MINOR_VERSION;')
if ! systemctl is-active --quiet "php${PHP_VER}-fpm" 2>/dev/null && ! systemctl is-active --quiet php-fpm 2>/dev/null; then
    print_info "Mengstart PHP-FPM..."
    apt-get install -y "php${PHP_VER}-fpm" 2>/dev/null || apt-get install -y php-fpm 2>/dev/null
    systemctl enable "php${PHP_VER}-fpm" 2>/dev/null || systemctl enable php-fpm 2>/dev/null
    systemctl start "php${PHP_VER}-fpm" 2>/dev/null || systemctl start php-fpm 2>/dev/null
fi

print_info "Membuat direktori API..."
mkdir -p "$API_DIR"

# Generate auth key if not exists
if [ ! -f /etc/xray/api_auth.key ]; then
    print_info "Membuat API Auth Key..."
    API_KEY=$(cat /proc/sys/kernel/random/uuid | tr -d '-' | head -c 10)
    echo "$API_KEY" > /etc/xray/api_auth.key
    chmod 600 /etc/xray/api_auth.key
    print_ok "Auth Key dibuat: $API_KEY"
else
    API_KEY=$(cat /etc/xray/api_auth.key)
    print_ok "Auth Key sudah ada: $API_KEY"
fi

DOMAIN=$(cat /etc/xray/domain 2>/dev/null)

print_info "Mendownload API scripts..."

# Download all API scripts from repo
for script in create-ssh trial-ssh create-vmess trial-vmess create-vless trial-vless create-trojan trial-trojan; do
    wget -q -O "$API_DIR/${script}.php" "${REPO}/${script}.php" 2>/dev/null
    if [ $? -ne 0 ]; then
        # Copy from local if wget fails
        cp /usr/bin/api-src/${script}.php "$API_DIR/" 2>/dev/null
    fi
    chmod 644 "$API_DIR/${script}.php"
done

# Download doc.html
wget -q -O "$API_DIR/doc.html" "${REPO}/doc.html" 2>/dev/null || cp /usr/bin/api-src/doc.html "$API_DIR/" 2>/dev/null

print_ok "API scripts selesai dipasang"

# Configure nginx for PHP & API
print_info "Mengkonfigurasi Nginx untuk API..."

NGINX_CONF="/etc/nginx/conf.d/xray.conf"
PHP_SOCK=$(ls /run/php/php*-fpm.sock 2>/dev/null | head -n1)
[ -z "$PHP_SOCK" ] && PHP_SOCK="/run/php/php-fpm.sock"

# Add PHP handler to nginx if not present
if ! grep -q "\.php\$" "$NGINX_CONF" 2>/dev/null; then
    # Add php location block before last closing brace
    sed -i 's|^}$|    location ~ \\.php$ {\n        include fastcgi_params;\n        fastcgi_pass unix:'"$PHP_SOCK"';\n        fastcgi_param SCRIPT_FILENAME $document_root$fastcgi_script_name;\n    }\n}|' "$NGINX_CONF" 2>/dev/null
fi

systemctl reload nginx 2>/dev/null
print_ok "Nginx dikonfigurasi"

# Create update-api command
cat > /usr/bin/update-api << 'UPDATEEOF'
#!/bin/bash
echo -e "\e[92m[*] Mengupdate API...\e[0m"
bash /usr/bin/api-install
echo -e "\e[92m[✔] API berhasil diupdate!\e[0m"
UPDATEEOF
chmod +x /usr/bin/update-api

print_ok "Command 'update-api' tersedia"
echo ""
echo -e "\033[96;1m┌─────────────────────────────────────────────────┐\033[0m"
echo -e "\033[96;1m│              API BERHASIL DIPASANG!             │\033[0m"
echo -e "\033[96;1m├─────────────────────────────────────────────────┤\033[0m"
echo -e " ${YELLOW}Auth Key   :${NC} ${Green}${API_KEY}${NC}"
echo -e " ${YELLOW}Domain     :${NC} ${Green}${DOMAIN}${NC}"
echo -e " ${YELLOW}API Docs   :${NC} ${BLUE}https://${DOMAIN}/api/doc.html${NC}"
echo -e ""
echo -e " ${YELLOW}Endpoints:${NC}"
echo -e "  ${BLUE}Trial SSH   :${NC} https://${DOMAIN}/api/trial-ssh?auth=${API_KEY}"
echo -e "  ${BLUE}Create SSH  :${NC} https://${DOMAIN}/api/create-ssh?auth=${API_KEY}&user=X&password=X&exp=30"
echo -e "  ${BLUE}Trial VMess :${NC} https://${DOMAIN}/api/trial-vmess?auth=${API_KEY}"
echo -e "  ${BLUE}Create VMess:${NC} https://${DOMAIN}/api/create-vmess?auth=${API_KEY}&user=X&exp=30"
echo -e "  ${BLUE}Trial VLess :${NC} https://${DOMAIN}/api/trial-vless?auth=${API_KEY}"
echo -e "  ${BLUE}Create VLess:${NC} https://${DOMAIN}/api/create-vless?auth=${API_KEY}&user=X&exp=30"
echo -e "  ${BLUE}Trial Trojan:${NC} https://${DOMAIN}/api/trial-trojan?auth=${API_KEY}"
echo -e "  ${BLUE}Create Trojan:${NC}https://${DOMAIN}/api/create-trojan?auth=${API_KEY}&user=X&exp=30"
echo -e "\033[96;1m└─────────────────────────────────────────────────┘\033[0m"
echo ""
read -n1 -s -r -p "Tekan tombol apa saja untuk kembali ke menu..."
menu 2>/dev/null
