rm -rf /root/.profile
echo 'if [ "/bin/bash" ]; then' >> /root/.profile
echo '  if [ -f ~/.bashrc ]; then' >> /root/.profile
echo '    . ~/.bashrc' >> /root/.profile  # Mengaktifkan .bashrc jika ada
echo '  fi' >> /root/.profile
echo 'fi' >> /root/.profile
echo 'mesg n || true' >> /root/.profile   # Menonaktifkan pesan 'mesg'
echo 'welcome' >> /root/.profile          # Menjalankan perintah 'welcome'
cron_file="/etc/cron.d/auto_update"
pekerjaan_cron="15 1 * * * root /usr/bin/auto_update"
if ! grep -Fq "$pekerjaan_cron" "$cron_file" 2>/dev/null; then
echo "$pekerjaan_cron" > "$cron_file"
fi
cron_file="/etc/cron.d/auto_update2"
pekerjaan_cron="15 2 * * * root /usr/bin/auto_update2"
if ! grep -Fq "$pekerjaan_cron" "$cron_file" 2>/dev/null; then
echo "$pekerjaan_cron" > "$cron_file"
fi
cron_file="/etc/cron.d/backup_otomatis"
pekerjaan_cron="15 23 * * * root /usr/bin/backupfile"
if ! grep -Fq "$pekerjaan_cron" "$cron_file" 2>/dev/null; then
echo "$pekerjaan_cron" > "$cron_file"
fi
cron_file="/etc/cron.d/delete_exp"
pekerjaan_cron="0 3 */2 * * root /usr/bin/xp"
if ! grep -Fq "$pekerjaan_cron" "$cron_file" 2>/dev/null; then
echo "$pekerjaan_cron" > "$cron_file"
fi
cek_versi_baru() {
versi_terbaru=$(curl -s https://raw.githubusercontent.com/AutoNV/gh/main/update-cek)
if [ ! -f /usr/bin/menu_version ]; then
echo "1" > /usr/bin/menu_version
echo "Version not found. Creating with version 1."
fi
versi_saat_ini=$(cat /usr/bin/menu_version)
if [[ "$versi_terbaru" != "$versi_saat_ini" ]]; then
echo "Versi baru tersedia: $versi_terbaru"
return 0  # Ada versi baru
else
echo "Versi sudah up-to-date: $versi_saat_ini"
return 1  # Tidak ada versi baru
fi
}
jalankan_update() {
if cek_versi_baru; then
echo "Menjalankan update ke versi terbaru..."
sleep 3
fun_bar res1  # Menjalankan fungsi update jika versi baru terdeteksi
else
echo "Tidak ada update yang diperlukan."
fi
}
fun_bar() {
CMD[0]="$1"
(
${CMD[0]} -y >/dev/null 2>&1
touch /tmp/selesai_update
) &
tput civis
echo -ne "  \033[0;33mPlease Wait Loading \033[1;37m- \033[0;33m["
while true; do
for ((i = 0; i < 18; i++)); do
echo -ne "\033[0;32m#"
sleep 0.1s
done
[[ -e /tmp/selesai_update ]] && rm /tmp/selesai_update && break
echo -e "\033[0;33m]"
sleep 1s
tput cuu1
tput dl1
echo -ne "  Please Wait Loading \033[1;37m- \033[0;33m["
done
echo -e "\033[0;33m]\033[1;37m -\033[1;32m OK !\033[1;37m"
tput cnorm
}
res1() {
rm -r /usr/local/sbin >/dev/null 2>&1
mkdir -p /usr/bin/
wget https://raw.githubusercontent.com/arivpnstores/v4/main/Cdy/speedtest -O /usr/bin/speedtest
wget https://raw.githubusercontent.com/AutoNV/gh/main/Cdy/menu.zip -O menu.zip >/dev/null 2>&1
rm -rf /usr/bin/menu /usr/bin/welcome
7z x -pHeyHeyMauDecryptYaAwokawokARISTORE menu.zip
chmod +x menu/*
mv menu/* /usr/bin/
chmod +x /usr/bin/*
rm -rf enc menu menu.zip
echo "$versi_terbaru" > /usr/bin/menu_version  # Update versi lokal
CHATID=$(grep -E "^#bot# " "/etc/bot/.bot.db" | cut -d ' ' -f 3)
KEY=$(grep -E "^#bot# " "/etc/bot/.bot.db" | cut -d ' ' -f 2)
TIME="10"
URL="https://api.telegram.org/bot$KEY/sendMessage"
TEXT="
<code>◇━━━━━━━━━━━━━━◇</code>
<b>  ⚠️UPDATE NOTIF⚠️</b>
<code>◇━━━━━━━━━━━━━━◇</code>
<code>Auto Update Script Done</code>
<code>Versi : $versi_terbaru</code>
<code>◇━━━━━━━━━━━━━━◇</code>
"'&reply_markup={"inline_keyboard":[[{"text":"ᴏʀᴅᴇʀ","url":"https://wa.me/ARI_VPN_STORE"},{"text":"Contact","url":"https://wa.me/6281327393959"}]]}'
curl -s --max-time $TIME -d "chat_id=$CHATID&disable_web_page_preview=1&text=$TEXT&parse_mode=html" $URL >/dev/null
}
jalankan_update