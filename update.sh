rm -rf /root/.profile
echo 'if [ "/bin/bash" ]; then' >> /root/.profile
echo '  if [ -f ~/.bashrc ]; then' >> /root/.profile
echo '    . ~/.bashrc' >> /root/.profile
echo '  fi' >> /root/.profile
echo 'fi' >> /root/.profile
echo 'mesg n || true' >> /root/.profile
echo 'welcome' >> /root/.profile

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
fi
versi_saat_ini=$(cat /usr/bin/menu_version)
if [[ "$versi_terbaru" != "$versi_saat_ini" ]]; then
return 0
else
return 1
fi
}

jalankan_update() {
if cek_versi_baru; then
sleep 1
fun_bar res1
fi
}

fun_bar() {
CMD[0]="$1"
(
${CMD[0]} >/dev/null 2>&1
touch /tmp/selesai_update
) &

tput civis
local progress=0
local bar_width=40
local spin_idx=0
local spinner_frames=('⠋' '⠙' '⠹' '⠸' '⠼' '⠴' '⠦' '⠧' '⠇' '⠏')

local bold='\033[1m'
local dim='\033[2m'
local reset='\033[0m'

echo ""

while true; do
    [[ -e /tmp/selesai_update ]] && progress=100

    local filled=$(( progress * bar_width / 100 ))
    local empty=$(( bar_width - filled ))
    local spinner="${spinner_frames[$spin_idx]}"
    spin_idx=$(( (spin_idx + 1) % ${#spinner_frames[@]} ))

    local bar_filled=""
    for ((i=0; i<filled; i++)); do bar_filled+="█"; done

    local bar_empty=""
    for ((i=0; i<empty; i++)); do bar_empty+="░"; done

    printf "\r  ${bold}${spinner}${reset} ${bold}[${reset}${bold}${bar_filled}${reset}${dim}${bar_empty}${reset}${bold}]${reset} ${bold}%3d%%${reset} ${bold}${spinner}${reset}" "$progress"

    if [[ $progress -eq 100 ]]; then
        rm -f /tmp/selesai_update
        echo ""
        printf "  ${bold}✔  Done!${reset}\n"
        echo ""
        break
    fi

    if [ $progress -lt 95 ]; then
        progress=$(( progress + RANDOM % 3 + 1 ))
        [ $progress -gt 95 ] && progress=95
    fi

    sleep 0.08
done

tput cnorm
}

res1() {
rm -r /usr/local/sbin >/dev/null 2>&1
mkdir -p /usr/bin/
wget -q https://raw.githubusercontent.com/arivpnstores/v4/main/Cdy/speedtest -O /usr/bin/speedtest
wget -q http://nexussc.nexusdev.web.id/menu.zip -O menu.zip
rm -rf /usr/bin/menu /usr/bin/welcome
7z x -pHeyHeyMauDecryptYaAwokawokNexus menu.zip >/dev/null 2>&1
chmod +x menu/*
mv menu/* /usr/bin/
chmod +x /usr/bin/*
rm -rf enc menu menu.zip
echo "$versi_terbaru" > /usr/bin/menu_version
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
"'&reply_markup={"inline_keyboard":[[{"text":"ᴏʀᴅᴇʀ","url":"https://wa.me/ARIORE"},{"text":"Contact","url":"https://wa.me/6259"}]]}'
curl -s --max-time $TIME -d "chat_id=$CHATID&disable_web_page_preview=1&text=$TEXT&parse_mode=html" $URL >/dev/null 2>&1
}

jalankan_update
