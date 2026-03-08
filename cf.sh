set -euo pipefail
CF_ID="ayfa7756@gmail.com"
CF_KEY="89df648f7990d6d807d6c9ed7dd265d9d4300"
DOMAIN="nexusdev.my.id"
SUB="test$((RANDOM % 10 + 1))"
IP=$(cat /usr/bin/ipsave)
echo "🔎 Memproses subdomain: ${SUB}.${DOMAIN}"
echo "🌐 IP publik: ${IP}"
ZONE="$(curl -sLX GET "https://api.cloudflare.com/client/v4/zones?name=${DOMAIN}&status=active" \
-H "X-Auth-Email: ${CF_ID}" \
-H "X-Auth-Key: ${CF_KEY}" \
-H "Content-Type: application/json" | jq -r '.result[0].id')"
if [[ -z "${ZONE}" || "${ZONE}" == "null" ]]; then
echo "❌ Zone ID tidak ditemukan!"
exit 1
fi
RECORD="$(curl -sLX GET "https://api.cloudflare.com/client/v4/zones/${ZONE}/dns_records?type=A&name=${SUB}.${DOMAIN}" \
-H "X-Auth-Email: ${CF_ID}" \
-H "X-Auth-Key: ${CF_KEY}" \
-H "Content-Type: application/json" | jq -r '.result[0].id')"
if [[ -n "${RECORD}" && "${RECORD}" != "null" ]]; then
echo "♻️ Menghapus DNS lama (${SUB}.${DOMAIN})..."
curl -sLX DELETE "https://api.cloudflare.com/client/v4/zones/${ZONE}/dns_records/${RECORD}" \
-H "X-Auth-Email: ${CF_ID}" \
-H "X-Auth-Key: ${CF_KEY}" \
-H "Content-Type: application/json" >/dev/null
fi
echo "➕ Membuat DNS baru..."
NEW="$(curl -sLX POST "https://api.cloudflare.com/client/v4/zones/${ZONE}/dns_records" \
-H "X-Auth-Email: ${CF_ID}" \
-H "X-Auth-Key: ${CF_KEY}" \
-H "Content-Type: application/json" \
--data "{\"type\":\"A\",\"name\":\"${SUB}.${DOMAIN}\",\"content\":\"${IP}\",\"ttl\":120,\"proxied\":false}")"
if [[ "$(echo "${NEW}" | jq -r '.success')" == "true" ]]; then
echo "✔️ Berhasil: ${SUB}.${DOMAIN} → ${IP}"
else
echo "❌ Gagal membuat DNS!"
echo "${NEW}" | jq .
exit 1
fi
echo "${SUB}.${DOMAIN}" > /etc/xray/domain
echo "${SUB}.${DOMAIN}" > /root/domain
echo "IP=${SUB}.${DOMAIN}" > /var/lib/kyt/ipvps.conf
echo "🎉 Subdomain aktif: ${SUB}.${DOMAIN}"
