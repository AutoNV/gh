#!/bin/bash

IZIN_URL="https://raw.githubusercontent.com/AutoNV/gh/main/ip"
CACHE_DIR="/tmp/izin_cache"
CACHE_FILE="$CACHE_DIR/iplist.txt"
IPSAVE_FILE="/usr/bin/ipsave"
USER_FILE="/usr/bin/user"
EXP_FILE="/usr/bin/e"

mkdir -p "$CACHE_DIR"

# ── Ambil IP publik ──────────────────────────────────────────────────────────
MYIP=$(curl -s --max-time 5 ipv4.icanhazip.com)
[[ -z "$MYIP" ]] && MYIP=$(curl -s --max-time 5 ifconfig.me)
[[ -z "$MYIP" ]] && MYIP=$(wget -qO- ipinfo.io/ip)
[[ -z "$MYIP" ]] && { echo "❌ Gagal mengambil IP"; exit 1; }

echo "$MYIP" > "$IPSAVE_FILE"
echo "🌐 IP Server: $MYIP"

# ── Download IP list (selalu fresh) ─────────────────────────────────────────
echo "📥 Mengambil daftar IP..."
curl -s --max-time 10 "$IZIN_URL" -o "$CACHE_FILE"

if [[ ! -s "$CACHE_FILE" ]]; then
  echo "❌ Gagal download daftar IP dari server"
  exit 1
fi

echo "📋 Isi daftar IP yang terdaftar:"
cat "$CACHE_FILE"
echo ""
echo "🔍 Mencari IP: $MYIP"

# ── Cek IP dengan berbagai format kemungkinan ────────────────────────────────
# Coba exact match dulu
DATA=$(grep -w "$MYIP" "$CACHE_FILE")

# Kalau tidak ketemu, coba partial match (antisipasi format berbeda)
if [[ -z "$DATA" ]]; then
  DATA=$(grep "$MYIP" "$CACHE_FILE")
fi

if [[ -z "$DATA" ]]; then
  echo ""
  echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
  echo "❌ IP TIDAK TERDAFTAR"
  echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
  echo "IP kamu   : $MYIP"
  echo "IP di list: (lihat di atas)"
  echo ""
  echo "📌 Solusi: Daftarkan IP $MYIP ke AutoNV"
  echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
  rm -f "$USER_FILE" "$EXP_FILE"
  exit 1
fi

USERNAME=$(echo "$DATA" | awk '{print $2}')
EXPIRED=$(echo "$DATA" | awk '{print $3}')

echo "$USERNAME" > "$USER_FILE"
echo "$EXPIRED" > "$EXP_FILE"

export IP="$MYIP"
export MYIP="$MYIP"

# ── Info kota & ISP ──────────────────────────────────────────────────────────
mkdir -p /etc/xray 2>/dev/null
city="$(curl -fsS --max-time 5 ipinfo.io/city 2>/dev/null | tr -d '\r')"
[ -n "$city" ] && echo "$city" > /etc/xray/city
isp="$(curl -fsS --max-time 5 ipinfo.io/org 2>/dev/null | tr -d '\r' | cut -d " " -f 2-10)"
[ -n "$isp" ] && echo "$isp" > /etc/xray/isp

# ── Generate domain ──────────────────────────────────────────────────────────
rm -f cf.sh
echo -e "\e[1;32mPlease Wait While We Generate Your Domain\e[0m"
wget -q https://raw.githubusercontent.com/AutoNV/gh/main/cf.sh -O cf.sh
chmod +x cf.sh
./cf.sh
domain=$(cat /etc/xray/domain 2>/dev/null)

clear
echo "━━━━━━━━━━━━━━━━━━━━━━"
echo " IZIN SCRIPT AKTIF ✅"
echo " USER   : $USERNAME"
echo " EXP    : $EXPIRED"
echo " IP     : $MYIP"
echo " CITY   : $city"
echo " ISP    : $isp"
echo " DOMAIN : $domain"
echo "━━━━━━━━━━━━━━━━━━━━━━"
sleep 2
clear
