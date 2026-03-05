/**
 * NEXUSDEV - REST API Service
 * Supports: SSH, VMess, VLess, Trojan (Create & Trial)
 * Listens on 127.0.0.1:7979 — Nginx proxies /api/ via HTTPS
 */

const http = require('http');
const fs = require('fs');
const url = require('url');

const PORT = 7979;
const HOST = '127.0.0.1';
const AUTH_KEY_PATH = '/etc/ssh/api_auth.key';

// ─── Helpers ───────────────────────────────────────────────────────────────

function readFile(path, fallback = '') {
  try { return fs.readFileSync(path, 'utf8').trim(); } catch { return fallback; }
}

function getAuth()   { return readFile(AUTH_KEY_PATH, ''); }
function getDomain() { return readFile('/etc/xray/domain', 'yourdomain.com'); }
function getIP()     { return readFile('/usr/bin/ipsave', ''); }
function getISP()    { return readFile('/etc/xray/isp', ''); }
function getCity()   { return readFile('/etc/xray/city', ''); }

function genUUID() {
  return 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, c => {
    const r = Math.random() * 16 | 0;
    return (c === 'x' ? r : (r & 0x3 | 0x8)).toString(16);
  });
}

function randomNum(min, max) {
  return Math.floor(Math.random() * (max - min + 1)) + min;
}

function dateAfterDays(days) {
  const d = new Date();
  d.setDate(d.getDate() + parseInt(days));
  return d;
}

function formatDateShort(d) {
  const m = ['Jan','Feb','Mar','Apr','May','Jun','Jul','Aug','Sep','Oct','Nov','Dec'];
  return `${String(d.getDate()).padStart(2,'0')} ${m[d.getMonth()]}, ${d.getFullYear()}`;
}

function sendJSON(res, statusCode, data) {
  res.writeHead(statusCode, {
    'Content-Type': 'application/json',
    'Access-Control-Allow-Origin': '*'
  });
  res.end(JSON.stringify(data, null, 2));
}

function sendHTML(res, html) {
  res.writeHead(200, {
    'Content-Type': 'text/html; charset=utf-8',
    'Access-Control-Allow-Origin': '*'
  });
  res.end(html);
}

function execCmd(cmd) {
  const { execSync } = require('child_process');
  try {
    return { ok: true, out: execSync(cmd, { encoding: 'utf8', timeout: 15000 }) };
  } catch(e) {
    return { ok: false, out: e.message };
  }
}

// ─── SSH ────────────────────────────────────────────────────────────────────

function handleCreateSSH(params, res) {
  const { user, password, exp, limitip } = params;
  if (!user || !password || !exp)
    return sendJSON(res, 400, { status: 'error', message: 'Required: user, password, exp' });

  const domain  = getDomain();
  const ip      = getIP();
  const isp     = getISP();
  const city    = getCity();
  const iplimit = limitip || '1';
  const expDate = dateAfterDays(exp);
  const expStr  = formatDateShort(expDate);
  const expISO  = expDate.toISOString().split('T')[0];
  const created = formatDateShort(new Date());

  execCmd(`useradd -e "${expISO}" -s /bin/false -M "${user}" 2>/dev/null || true`);
  execCmd(`echo -e "${password}\\n${password}" | passwd "${user}" 2>/dev/null || true`);
  if (parseInt(iplimit) > 0)
    execCmd(`mkdir -p /etc/kyt/limit/ssh/ip && echo "${iplimit}" > /etc/kyt/limit/ssh/ip/${user}`);
  execCmd(`grep -v "^#ssh# ${user} " /etc/ssh/.ssh.db > /tmp/ssh.db.tmp 2>/dev/null && mv /tmp/ssh.db.tmp /etc/ssh/.ssh.db || true`);
  execCmd(`echo "#ssh# ${user} ${password} 0 ${iplimit} ${expStr}" >> /etc/ssh/.ssh.db`);

  const txtContent = `==============================
SSH OVPN Account
==============================
Username         : ${user}
Password         : ${password}
IP               : ${ip}
Host             : ${domain}
Port OpenSSH     : 443, 80, 22
Port Dropbear    : 443, 109
Port SSH WS      : 80, 8080, 8081-9999
Port SSH SSL WS  : 443
Port SSH UDP     : 1-65535
Port SSL/TLS     : 400-900
Port OVPN WS SSL : 443
Port OVPN SSL    : 443
Port OVPN TCP    : 1194
Port OVPN UDP    : 2200
BadVPN UDP       : 7100, 7300
==============================
Payload : GET / HTTP/1.1[crlf]Host: [host][crlf]Upgrade: websocket[crlf][crlf]
OVPN Download : https://${domain}:81/
Expired       : ${expStr}
==============================`;
  try { fs.writeFileSync(`/var/www/html/ssh-${user}.txt`, txtContent); } catch {}

  sendJSON(res, 200, {
    status: 'success',
    data: {
      username: user,
      password: password,
      host: domain,
      ip: ip,
      ports: {
        openSSH: '22',
        dropbear: '143, 109',
        dropbearWS: '443, 109',
        sshUDP: '1-65535',
        ovpnWSSSL: '443',
        ovpnSSL: '443',
        ovpnTCP: '1194',
        ovpnUDP: '2200',
        badVPN: '7100, 7300',
        sshWS: '80, 8080',
        sshWSSSL: '443'
      },
      formats: {
        port80:  `${domain}:80@${user}:${password}`,
        port443: `${domain}:443@${user}:${password}`,
        udp:     `${domain}:54-65535@${user}:${password}`
      },
      ovpnDownload: `https://${domain}:81`,
      saveLink: `https://${domain}:81/ssh-${user}.txt`,
      payloads: {
        wsNtls:   `GET / HTTP/1.1[crlf]Host: [host][crlf]Connection: Upgrade[crlf]User-Agent: [ua][crlf]Upgrade: ws[crlf][crlf]`,
        wsTls:    `GET wss://${domain}/ HTTP/1.1[crlf]Host: [host][crlf]Connection: Upgrade[crlf]User-Agent: [ua][crlf]Upgrade: ws[crlf][crlf]`,
        enhanced: `PATCH / HTTP/1.1[crlf]Host: ${domain}[crlf]Host: bug.com[crlf]Upgrade: websocket[crlf]Connection: Upgrade[crlf][crlf]`
      },
      created: created,
      expired: `${exp} Days`,
      expiredDate: expStr,
      limitIP: iplimit,
      isp: isp,
      city: city
    }
  });
}

function handleTrialSSH(params, res) {
  const domain   = getDomain();
  const ip       = getIP();
  const isp      = getISP();
  const city     = getCity();
  const user     = `Trial${randomNum(10000,99999)}`;
  const password = '1';
  const iplimit  = '99';
  const expDate  = dateAfterDays(0);
  const expISO   = expDate.toISOString().split('T')[0];
  const created  = formatDateShort(new Date());

  execCmd(`useradd -e "${expISO}" -s /bin/false -M "${user}" 2>/dev/null || true`);
  execCmd(`echo -e "${password}\\n${password}" | passwd "${user}" 2>/dev/null || true`);
  execCmd(`mkdir -p /etc/kyt/limit/ssh/ip && echo "${iplimit}" > /etc/kyt/limit/ssh/ip/${user}`);

  sendJSON(res, 200, {
    status: 'success',
    data: {
      username: user,
      password: password,
      host: domain,
      ip: ip,
      ports: {
        openSSH: '22', dropbear: '143, 109', dropbearWS: '443, 109',
        sshUDP: '1-65535', ovpnWSSSL: '443', ovpnSSL: '443',
        ovpnTCP: '1194', ovpnUDP: '2200', badVPN: '7100, 7300',
        sshWS: '80, 8080', sshWSSSL: '443'
      },
      formats: {
        port80:  `${domain}:80@${user}:${password}`,
        port443: `${domain}:443@${user}:${password}`,
        udp:     `${domain}:54-65535@${user}:${password}`
      },
      ovpnDownload: `https://${domain}:81`,
      saveLink: `https://${domain}:81/ssh-${user}.txt`,
      payloads: {
        wsNtls:   `GET / HTTP/1.1[crlf]Host: [host][crlf]Connection: Upgrade[crlf]User-Agent: [ua][crlf]Upgrade: ws[crlf][crlf]`,
        wsTls:    `GET wss://${domain}/ HTTP/1.1[crlf]Host: [host][crlf]Connection: Upgrade[crlf]User-Agent: [ua][crlf]Upgrade: ws[crlf][crlf]`,
        enhanced: `PATCH / HTTP/1.1[crlf]Host: ${domain}[crlf]Host: bug.com[crlf]Upgrade: websocket[crlf]Connection: Upgrade[crlf][crlf]`
      },
      created: created,
      expired: '60 Minutes',
      isp: isp,
      city: city
    }
  });
}

// ─── VMess ──────────────────────────────────────────────────────────────────

function buildVmessLinks(user, uuid, domain) {
  const wsTls  = { v:'2', ps:`${user}-TLS`,     add:domain, port:'443', id:uuid, aid:'0', net:'ws',   type:'none', host:domain, path:'/vmess',     tls:'tls'  };
  const wsNtls = { v:'2', ps:`${user}-NoneTLS`, add:domain, port:'80',  id:uuid, aid:'0', net:'ws',   type:'none', host:domain, path:'/vmess',     tls:'none' };
  const grpc   = { v:'2', ps:`${user}-gRPC`,    add:domain, port:'443', id:uuid, aid:'0', net:'grpc', type:'none', host:'',     path:'vmess-grpc', tls:'tls'  };
  return {
    ws_tls:      `vmess://${Buffer.from(JSON.stringify(wsTls)).toString('base64')}`,
    ws_none_tls: `vmess://${Buffer.from(JSON.stringify(wsNtls)).toString('base64')}`,
    grpc:        `vmess://${Buffer.from(JSON.stringify(grpc)).toString('base64')}`
  };
}

function handleCreateVmess(params, res) {
  const { user, quota, limitip, exp } = params;
  if (!user || !exp)
    return sendJSON(res, 400, { status: 'error', message: 'Required: user, exp' });

  const domain  = getDomain();
  const uuid    = genUUID();
  const expDate = dateAfterDays(exp);
  const expISO  = expDate.toISOString().split('T')[0];
  const expStr  = formatDateShort(expDate);
  const iplimit = limitip || '1';
  const links   = buildVmessLinks(user, uuid, domain);

  execCmd(`sed -i '/#vmess$/a\\### ${user} ${expISO}\\\\\\n},{\"id\": \"${uuid}\",\"alterId\": 0,\"email\": \"${user}\"' /etc/xray/config.json 2>/dev/null || true`);
  execCmd(`sed -i '/#vmessgrpc$/a\\### ${user} ${expISO}\\\\\\n},{\"id\": \"${uuid}\",\"alterId\": 0,\"email\": \"${user}\"' /etc/xray/config.json 2>/dev/null || true`);
  if (parseInt(iplimit) > 0)
    execCmd(`mkdir -p /etc/kyt/limit/vmess/ip && echo "${iplimit}" > /etc/kyt/limit/vmess/ip/${user}`);
  execCmd(`grep -v "^### ${user} " /etc/vmess/.vmess.db > /tmp/vm.tmp 2>/dev/null && mv /tmp/vm.tmp /etc/vmess/.vmess.db || true`);
  execCmd(`echo "### ${user} ${expISO} ${uuid} ${quota||0} ${iplimit}" >> /etc/vmess/.vmess.db`);
  execCmd(`systemctl restart xray 2>/dev/null || true`);

  sendJSON(res, 200, {
    status: 'success',
    data: {
      user, uuid,
      expired: `${exp} Days`,
      expiredDate: expStr,
      domain,
      quota: `${quota||0} GB`,
      limitIP: iplimit,
      ws_tls: links.ws_tls,
      ws_none_tls: links.ws_none_tls,
      grpc: links.grpc,
      openclash: `https://${domain}:81/vmess-${user}.txt`,
      dashboard_url: `https://${domain}/api/vmess-${user}.html`
    }
  });
}

function handleTrialVmess(params, res) {
  const domain  = getDomain();
  const user    = `Trial${randomNum(1000,9999)}`;
  const uuid    = genUUID();
  const expDate = dateAfterDays(0);
  const expISO  = expDate.toISOString().split('T')[0];
  const links   = buildVmessLinks(user, uuid, domain);

  execCmd(`sed -i '/#vmess$/a\\### ${user} ${expISO}\\\\\\n},{\"id\": \"${uuid}\",\"alterId\": 0,\"email\": \"${user}\"' /etc/xray/config.json 2>/dev/null || true`);
  execCmd(`sed -i '/#vmessgrpc$/a\\### ${user} ${expISO}\\\\\\n},{\"id\": \"${uuid}\",\"alterId\": 0,\"email\": \"${user}\"' /etc/xray/config.json 2>/dev/null || true`);
  execCmd(`systemctl restart xray 2>/dev/null || true`);

  sendJSON(res, 200, {
    status: 'success',
    data: {
      user, uuid,
      expired: '60 minutes',
      domain,
      ws_tls: links.ws_tls,
      ws_none_tls: links.ws_none_tls,
      grpc: links.grpc,
      openclash: `https://${domain}:81/vmess-${user}.txt`,
      dashboard_url: `https://${domain}/api/vmess-${user}.html`
    }
  });
}

// ─── VLess ──────────────────────────────────────────────────────────────────

function buildVlessLinks(user, uuid, domain) {
  return {
    ws_tls:      `vless://${uuid}@${domain}:443?path=%2Fvless&security=tls&encryption=none&type=ws#${user}-TLS`,
    ws_none_tls: `vless://${uuid}@${domain}:80?path=%2Fvless&encryption=none&type=ws#${user}-NoneTLS`,
    grpc:        `vless://${uuid}@${domain}:443?mode=gun&security=tls&encryption=none&type=grpc&serviceName=vless-grpc&sni=${domain}#${user}-gRPC`
  };
}

function handleCreateVless(params, res) {
  const { user, quota, limitip, exp } = params;
  if (!user || !exp)
    return sendJSON(res, 400, { status: 'error', message: 'Required: user, exp' });

  const domain  = getDomain();
  const uuid    = genUUID();
  const expDate = dateAfterDays(exp);
  const expISO  = expDate.toISOString().split('T')[0];
  const expStr  = formatDateShort(expDate);
  const iplimit = limitip || '1';
  const links   = buildVlessLinks(user, uuid, domain);

  execCmd(`sed -i '/#vless$/a\\#& ${user} ${expISO}\\\\\\n},{\"id\": \"${uuid}\",\"email\": \"${user}\"' /etc/xray/config.json 2>/dev/null || true`);
  execCmd(`sed -i '/#vlessgrpc$/a\\#& ${user} ${expISO}\\\\\\n},{\"id\": \"${uuid}\",\"email\": \"${user}\"' /etc/xray/config.json 2>/dev/null || true`);
  if (parseInt(iplimit) > 0)
    execCmd(`mkdir -p /etc/kyt/limit/vless/ip && echo "${iplimit}" > /etc/kyt/limit/vless/ip/${user}`);
  execCmd(`grep -v "^#& ${user} " /etc/vless/.vless.db > /tmp/vl.tmp 2>/dev/null && mv /tmp/vl.tmp /etc/vless/.vless.db || true`);
  execCmd(`echo "#& ${user} ${expISO} ${uuid} ${quota||0} ${iplimit}" >> /etc/vless/.vless.db`);
  execCmd(`systemctl restart xray 2>/dev/null || true`);

  sendJSON(res, 200, {
    status: 'success',
    data: {
      user, uuid,
      expired: `${exp} Days`,
      expiredDate: expStr,
      domain,
      quota: `${quota||0} GB`,
      limitIP: iplimit,
      ws_tls: links.ws_tls,
      ws_none_tls: links.ws_none_tls,
      grpc: links.grpc,
      openclash: `https://${domain}:81/vless-${user}.txt`,
      dashboard_url: `https://${domain}/api/vless-${user}.html`
    }
  });
}

function handleTrialVless(params, res) {
  const domain  = getDomain();
  const user    = `Trial${randomNum(1000,9999)}`;
  const uuid    = genUUID();
  const expDate = dateAfterDays(0);
  const expISO  = expDate.toISOString().split('T')[0];
  const links   = buildVlessLinks(user, uuid, domain);

  execCmd(`sed -i '/#vless$/a\\#& ${user} ${expISO}\\\\\\n},{\"id\": \"${uuid}\",\"email\": \"${user}\"' /etc/xray/config.json 2>/dev/null || true`);
  execCmd(`sed -i '/#vlessgrpc$/a\\#& ${user} ${expISO}\\\\\\n},{\"id\": \"${uuid}\",\"email\": \"${user}\"' /etc/xray/config.json 2>/dev/null || true`);
  execCmd(`systemctl restart xray 2>/dev/null || true`);

  sendJSON(res, 200, {
    status: 'success',
    data: {
      user, uuid,
      expired: '60 minutes',
      domain,
      ws_tls: links.ws_tls,
      ws_none_tls: links.ws_none_tls,
      grpc: links.grpc,
      openclash: `https://${domain}:81/vless-${user}.txt`,
      dashboard_url: `https://${domain}/api/vless-${user}.html`
    }
  });
}

// ─── Trojan ─────────────────────────────────────────────────────────────────

function buildTrojanLinks(user, uuid, domain) {
  return {
    ws:   `trojan://${uuid}@${domain}:443?path=%2Ftrojan-ws&security=tls&host=${domain}&type=ws&sni=${domain}#${user}`,
    grpc: `trojan://${uuid}@${domain}:443?mode=gun&security=tls&type=grpc&serviceName=trojan-grpc&sni=${domain}#${user}`
  };
}

function handleCreateTrojan(params, res) {
  const { user, quota, limitip, exp } = params;
  if (!user || !exp)
    return sendJSON(res, 400, { status: 'error', message: 'Required: user, exp' });

  const domain  = getDomain();
  const uuid    = genUUID();
  const expDate = dateAfterDays(exp);
  const expISO  = expDate.toISOString().split('T')[0];
  const expStr  = formatDateShort(expDate);
  const iplimit = limitip || '1';
  const links   = buildTrojanLinks(user, uuid, domain);

  execCmd(`sed -i '/#trojanws$/a\\#! ${user} ${expISO}\\\\\\n},{\"password\": \"${uuid}\",\"email\": \"${user}\"' /etc/xray/config.json 2>/dev/null || true`);
  execCmd(`sed -i '/#trojangrpc$/a\\#! ${user} ${expISO}\\\\\\n},{\"password\": \"${uuid}\",\"email\": \"${user}\"' /etc/xray/config.json 2>/dev/null || true`);
  if (parseInt(iplimit) > 0)
    execCmd(`mkdir -p /etc/kyt/limit/trojan/ip && echo "${iplimit}" > /etc/kyt/limit/trojan/ip/${user}`);
  execCmd(`grep -v "^### ${user} " /etc/trojan/.trojan.db > /tmp/tr.tmp 2>/dev/null && mv /tmp/tr.tmp /etc/trojan/.trojan.db || true`);
  execCmd(`echo "### ${user} ${expISO} ${uuid} ${quota||0} ${iplimit}" >> /etc/trojan/.trojan.db`);
  execCmd(`systemctl restart xray 2>/dev/null || true`);

  sendJSON(res, 200, {
    status: 'success',
    data: {
      user, uuid,
      expired: `${exp} Days`,
      expiredDate: expStr,
      domain,
      quota: `${quota||0} GB`,
      limitIP: iplimit,
      ws: links.ws,
      grpc: links.grpc,
      openclash: `https://${domain}:81/trojan-${user}.txt`,
      dashboard_url: `https://${domain}/api/trojan-${user}.html`
    }
  });
}

function handleTrialTrojan(params, res) {
  const domain  = getDomain();
  const user    = `Trial${randomNum(1000,9999)}`;
  const uuid    = genUUID();
  const expDate = dateAfterDays(0);
  const expISO  = expDate.toISOString().split('T')[0];
  const links   = buildTrojanLinks(user, uuid, domain);

  execCmd(`sed -i '/#trojanws$/a\\#! ${user} ${expISO}\\\\\\n},{\"password\": \"${uuid}\",\"email\": \"${user}\"' /etc/xray/config.json 2>/dev/null || true`);
  execCmd(`sed -i '/#trojangrpc$/a\\#! ${user} ${expISO}\\\\\\n},{\"password\": \"${uuid}\",\"email\": \"${user}\"' /etc/xray/config.json 2>/dev/null || true`);
  execCmd(`systemctl restart xray 2>/dev/null || true`);

  sendJSON(res, 200, {
    status: 'success',
    data: {
      user, uuid,
      expired: '60 minutes',
      domain,
      ws: links.ws,
      grpc: links.grpc,
      openclash: `https://${domain}:81/trojan-${user}.txt`,
      dashboard_url: `https://${domain}/api/trojan-${user}.html`
    }
  });
}

// ─── API Doc Page ────────────────────────────────────────────────────────────

function handleDocLogin(res, domain) {
  const html = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1.0">
<title>NEXUSDEV — API Login</title>
<style>
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:'Segoe UI',sans-serif;background:linear-gradient(135deg,#e0f2fe 0%,#f0fdf4 50%,#fef3c7 100%);color:#1e293b;min-height:100vh;display:flex;align-items:center;justify-content:center}
.card{background:#fff;border:1px solid #e2e8f0;border-radius:18px;padding:44px 38px;width:100%;max-width:400px;text-align:center;box-shadow:0 20px 60px rgba(0,0,0,.1)}
.logo{font-size:2.8rem;margin-bottom:10px}
h1{color:#0369a1;font-size:1.4rem;margin-bottom:6px;font-weight:800}
p{color:#64748b;font-size:.84rem;margin-bottom:28px;line-height:1.6}
input{width:100%;background:#f8fafc;border:1.5px solid #e2e8f0;border-radius:10px;padding:12px 14px;color:#1e293b;font-size:.95rem;outline:none;margin-bottom:14px;transition:border .2s}
input:focus{border-color:#0ea5e9;box-shadow:0 0 0 3px rgba(14,165,233,.12)}
button{width:100%;background:linear-gradient(135deg,#0ea5e9,#6366f1);border:none;border-radius:10px;padding:12px;color:#fff;font-size:.96rem;font-weight:700;cursor:pointer;transition:opacity .2s}
button:hover{opacity:.9}
button:hover{background:#2ea043}
</style>
</head>
<body>
<div class="card">
  <div class="logo">⚡</div>
  <h1>NEXUSDEV API v1</h1>
  <p>Masukkan Auth Key untuk mengakses<br>dokumentasi API</p>
  <input type="password" id="key" placeholder="Auth Key..." onkeydown="if(event.key==='Enter')login()">
  <button onclick="login()">Masuk →</button>
</div>
<script>
function login(){
  const k=document.getElementById('key').value.trim();
  if(!k)return;
  window.location.href='/api/doc.html?auth='+encodeURIComponent(k);
}
</script>
</body></html>`;
  sendHTML(res, html);
}


function handleDocPage(params, res) {
  const domain  = getDomain();
  const auth    = getAuth();
  const baseUrl = `https://${domain}`;

  if (auth && params.auth !== auth) return handleDocLogin(res, domain);

  const renSample = JSON.stringify({
    status: "success",
    data: {
      username: "gua12",
      previous_expiry: "Mar 06, 2026",
      days_added: 1,
      expired: "2026-03-07",
      main_updated: true,
      grpc_updated: false
    }
  }, null, 2);

  const html = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1.0">
<title>NEXUSDEV API Docs</title>
<style>
:root{
  --bg:#f0f9ff;--card:#ffffff;--border:#bae6fd;--border2:#e0f2fe;
  --accent:#0284c7;--accent2:#6366f1;--accent3:#059669;--accent4:#d97706;--accent5:#dc2626;
  --text:#0f172a;--muted:#64748b;--muted2:#475569;
  --ssh:#059669;--vmess:#2563eb;--vless:#7c3aed;--trojan:#e11d48;
  --trial:#d97706;--del:#dc2626;--ren:#0891b2;
}
*{box-sizing:border-box;margin:0;padding:0}
html{scroll-behavior:smooth}
body{font-family:'Segoe UI',system-ui,sans-serif;background:var(--bg);color:var(--text);min-height:100vh;overflow-x:hidden}
body::before{content:'';position:fixed;inset:0;z-index:0;pointer-events:none;
  background:radial-gradient(ellipse 80% 60% at 10% 10%,#e0f2fe88,transparent),
             radial-gradient(ellipse 60% 50% at 90% 0%,#ede9fe55,transparent),
             radial-gradient(ellipse 70% 60% at 50% 100%,#dcfce755,transparent)}
.wrap{position:relative;z-index:1;max-width:1060px;margin:0 auto;padding:0 16px 80px}

/* ── Header ── */
.hdr{background:rgba(255,255,255,.85);border-bottom:1.5px solid var(--border);padding:0 24px;
     position:sticky;top:0;z-index:100;backdrop-filter:blur(16px);
     box-shadow:0 2px 16px rgba(2,132,199,.08)}
.hdr-in{max-width:1060px;margin:0 auto;height:64px;display:flex;align-items:center;justify-content:space-between;gap:12px}
.logo{display:flex;align-items:center;gap:10px}
.logo-ic{width:38px;height:38px;background:linear-gradient(135deg,var(--accent),var(--accent2));
         border-radius:10px;display:flex;align-items:center;justify-content:center;
         font-size:1.15rem;box-shadow:0 4px 14px rgba(2,132,199,.28);flex-shrink:0}
.logo-tx{font-size:1.05rem;font-weight:800;letter-spacing:.03em}
.logo-tx span{color:var(--accent)}
.logo-tx small{color:var(--muted);font-weight:400;font-size:.78rem}
.hdr-r{display:flex;align-items:center;gap:8px;flex-wrap:wrap}
.badge{padding:3px 10px;border-radius:20px;font-size:.67rem;font-weight:700;letter-spacing:.05em}
.bl{background:#dcfce7;color:#166534;border:1px solid #bbf7d0}
.bv{background:#e0f2fe;color:#075985;border:1px solid #bae6fd}
.key-pill{background:#fefce8;border:1px solid #fde68a;border-radius:7px;padding:4px 10px;
          font-size:.71rem;color:#92400e;display:flex;align-items:center;gap:5px;
          max-width:200px;overflow:hidden}
.key-pill span{overflow:hidden;text-overflow:ellipsis;white-space:nowrap;font-family:monospace}

/* ── Hero ── */
.hero{padding:48px 0 32px;text-align:center}
.hero-tag{display:inline-flex;align-items:center;gap:6px;background:#e0f2fe;
          border:1.5px solid var(--border);border-radius:20px;padding:5px 16px;
          font-size:.71rem;color:#0369a1;letter-spacing:.07em;margin-bottom:18px;font-weight:700}
.hero h1{font-size:2.6rem;font-weight:900;letter-spacing:-.03em;margin-bottom:12px;line-height:1.1}
.hero h1 .gr{background:linear-gradient(120deg,var(--accent),var(--accent2) 60%,#a855f7);
             -webkit-background-clip:text;-webkit-text-fill-color:transparent}
.hero p{color:var(--muted2);font-size:.91rem;max-width:480px;margin:0 auto 26px;line-height:1.7}
.base-box{display:inline-flex;align-items:center;gap:10px;background:#fff;
          border:1.5px solid var(--border);border-radius:10px;padding:10px 20px;
          font-size:.83rem;box-shadow:0 2px 10px rgba(2,132,199,.1)}
.base-box .lbl{color:var(--muted);font-weight:600}
.base-box .val{color:var(--accent);font-weight:700;font-family:'Fira Code','SF Mono',monospace}

/* ── Stats ── */
.stats{display:grid;grid-template-columns:repeat(auto-fit,minmax(130px,1fr));gap:10px;margin:28px 0}
.stat{background:#fff;border:1.5px solid var(--border2);border-radius:14px;padding:18px 10px;
      text-align:center;position:relative;overflow:hidden;
      box-shadow:0 2px 8px rgba(0,0,0,.04);transition:transform .18s,box-shadow .18s}
.stat:hover{transform:translateY(-3px);box-shadow:0 8px 24px rgba(0,0,0,.08)}
.stat::before{content:'';position:absolute;top:0;left:0;right:0;height:4px;border-radius:4px 4px 0 0}
.st1::before{background:linear-gradient(90deg,var(--ssh),#34d399)}
.st2::before{background:linear-gradient(90deg,var(--vmess),#60a5fa)}
.st3::before{background:linear-gradient(90deg,var(--vless),#a78bfa)}
.st4::before{background:linear-gradient(90deg,var(--trojan),#fb7185)}
.st5::before{background:linear-gradient(90deg,var(--del),#f87171)}
.st6::before{background:linear-gradient(90deg,var(--ren),#22d3ee)}
.stat-n{font-size:1.9rem;font-weight:900;margin-bottom:4px}
.st1 .stat-n{color:var(--ssh)}.st2 .stat-n{color:var(--vmess)}.st3 .stat-n{color:var(--vless)}
.st4 .stat-n{color:var(--trojan)}.st5 .stat-n{color:var(--del)}.st6 .stat-n{color:var(--ren)}
.stat-l{font-size:.66rem;color:var(--muted);letter-spacing:.07em;font-weight:700}

/* ── Tabs ── */
.tabs{display:flex;gap:5px;flex-wrap:wrap;margin:26px 0 0;border-bottom:2px solid var(--border);padding-bottom:0}
.tab{padding:9px 15px;border-radius:8px 8px 0 0;font-size:.76rem;font-weight:700;cursor:pointer;
     border:1.5px solid transparent;border-bottom:none;transition:all .15s;
     color:var(--muted);margin-bottom:-2px;background:transparent}
.tab:hover{background:#f0f9ff;color:var(--text)}
.tab.active{background:#fff;border-color:var(--border);border-bottom-color:#fff;color:var(--text)}
.tab.active.ts{border-top:3px solid var(--ssh);color:var(--ssh)}
.tab.active.tv{border-top:3px solid var(--vmess);color:var(--vmess)}
.tab.active.tvl{border-top:3px solid var(--vless);color:var(--vless)}
.tab.active.ttr{border-top:3px solid var(--trojan);color:var(--trojan)}
.tab.active.tdl{border-top:3px solid var(--del);color:var(--del)}
.tab.active.trn{border-top:3px solid var(--ren);color:var(--ren)}
.tc{display:none}.tc.active{display:block}

/* ── Section header ── */
.sh{display:flex;align-items:center;gap:10px;margin:26px 0 12px}
.sh-dot{width:8px;height:8px;border-radius:50%;flex-shrink:0}
.sh-lbl{font-size:.67rem;font-weight:800;letter-spacing:.12em;color:var(--muted);white-space:nowrap}
.sh-line{flex:1;height:1.5px;background:linear-gradient(90deg,var(--border),transparent)}

/* ── Endpoint card ── */
.ep{background:#fff;border:1.5px solid var(--border2);border-radius:14px;margin-bottom:9px;
    overflow:hidden;transition:border-color .15s,box-shadow .15s;
    box-shadow:0 1px 4px rgba(0,0,0,.04)}
.ep:hover{border-color:var(--border);box-shadow:0 4px 18px rgba(2,132,199,.1)}
.ep-hd{display:flex;align-items:center;gap:10px;padding:13px 16px;cursor:pointer;transition:background .12s}
.ep-hd:hover{background:#f8faff}
.mth{padding:4px 9px;border-radius:6px;font-size:.66rem;font-weight:800;min-width:42px;
     text-align:center;letter-spacing:.04em;font-family:monospace;flex-shrink:0}
.mg{background:#dcfce7;color:#166534;border:1px solid #bbf7d0}
.md{background:#fee2e2;color:#991b1b;border:1px solid #fecaca}
.mr{background:#cffafe;color:#155e75;border:1px solid #a5f3fc}
.ep-path{font-size:.84rem;flex:1;color:var(--text);font-family:'Fira Code','SF Mono',monospace;font-weight:600}
.ep-path .pm{color:var(--accent2);font-size:.76rem;font-weight:400}
.ep-dsc{font-size:.72rem;color:var(--muted);font-style:italic;white-space:nowrap}
.tags{display:flex;gap:4px;align-items:center;flex-wrap:wrap}
.tag{font-size:.61rem;padding:2px 7px;border-radius:10px;font-weight:700;letter-spacing:.03em;white-space:nowrap}
.tg-ssh{background:#d1fae5;color:#065f46;border:1px solid #a7f3d0}
.tg-vmess{background:#dbeafe;color:#1e40af;border:1px solid #bfdbfe}
.tg-vless{background:#ede9fe;color:#4c1d95;border:1px solid #ddd6fe}
.tg-trojan{background:#ffe4e6;color:#9f1239;border:1px solid #fecdd3}
.tg-trial{background:#fef3c7;color:#78350f;border:1px solid #fde68a}
.tg-del{background:#fee2e2;color:#991b1b;border:1px solid #fecaca}
.tg-ren{background:#cffafe;color:#164e63;border:1px solid #a5f3fc}
.chev{color:var(--muted);font-size:.68rem;transition:transform .2s;flex-shrink:0}
.ep-bd{display:none;border-top:1.5px solid var(--border2);padding:18px;background:#fafcff}
.ep-bd.open{display:block}

/* ── Param table ── */
.pt{width:100%;border-collapse:collapse;font-size:.77rem;margin-bottom:14px}
.pt th{background:#f1f5f9;color:var(--muted);text-align:left;padding:7px 12px;
       font-weight:800;border-bottom:2px solid var(--border);font-size:.68rem;letter-spacing:.06em}
.pt td{padding:7px 12px;border-bottom:1px solid #f0f9ff;vertical-align:top;color:var(--muted2)}
.pt td:first-child{color:var(--accent2);font-family:monospace;font-size:.8rem;font-weight:700}
.req{background:#fee2e2;color:#dc2626;border:1px solid #fecaca;
     padding:2px 7px;border-radius:4px;font-size:.62rem;font-weight:800}
.opt{background:#dcfce7;color:#15803d;border:1px solid #bbf7d0;
     padding:2px 7px;border-radius:4px;font-size:.62rem;font-weight:800}

/* ── URL box ── */
.ul{font-size:.66rem;color:var(--muted);letter-spacing:.07em;margin-bottom:5px;font-weight:800}
.ub{background:#f0f9ff;border:1.5px solid var(--border);border-radius:9px;
    padding:10px 14px;font-size:.74rem;color:#0369a1;word-break:break-all;
    margin-bottom:12px;position:relative;padding-right:82px;line-height:1.55;
    font-family:'Fira Code','SF Mono',monospace}
.cp{position:absolute;right:10px;top:50%;transform:translateY(-50%);
    background:#e0f2fe;border:1px solid var(--border);color:#0369a1;
    padding:4px 10px;border-radius:6px;cursor:pointer;font-size:.66rem;
    font-weight:800;white-space:nowrap;transition:all .15s}
.cp:hover{background:var(--border)}.cp.ok{background:#dcfce7;border-color:#bbf7d0;color:#15803d}

/* ── Response box ── */
.rl{font-size:.66rem;color:var(--muted);letter-spacing:.07em;margin-bottom:5px;font-weight:800}
.rb{background:#0f172a;border:1px solid #1e293b;border-radius:9px;
    padding:14px;font-size:.75rem;line-height:1.8;max-height:260px;overflow-y:auto;
    color:#94a3b8;font-family:'Fira Code','SF Mono',monospace}
.rb .k{color:#7dd3fc}.rb .s{color:#86efac}.rb .n{color:#fcd34d}.rb .b{color:#f9a8d4}

/* ── Try it ── */
.try-sec{background:linear-gradient(135deg,#e0f2fe,#f0fdf4 60%);
         border:1.5px solid var(--border);border-radius:12px;padding:16px;margin-top:14px}
.try-ttl{font-size:.7rem;color:#0369a1;letter-spacing:.09em;margin-bottom:12px;font-weight:800}
.try-ins{display:flex;flex-wrap:wrap;gap:8px;margin-bottom:8px}
.ti{background:#fff;border:1.5px solid var(--border);border-radius:7px;
    padding:8px 11px;color:var(--text);font-size:.77rem;flex:1;min-width:100px;outline:none}
.ti:focus{border-color:var(--accent);box-shadow:0 0 0 3px rgba(2,132,199,.1)}
.ti::placeholder{color:#94a3b8}
.tr-btn{border:none;border-radius:7px;padding:8px 18px;color:#fff;
        font-size:.77rem;font-weight:800;cursor:pointer;white-space:nowrap;transition:opacity .15s}
.tr-btn:hover{opacity:.88}
.tr-go{background:linear-gradient(135deg,var(--accent),var(--accent2))}
.tr-del{background:linear-gradient(135deg,#ef4444,#b91c1c)}
.tr-ren{background:linear-gradient(135deg,var(--ren),#0e7490)}
.try-out{background:#0f172a;border:1px solid #1e293b;border-radius:7px;
         padding:12px;font-size:.73rem;color:#94a3b8;max-height:220px;overflow-y:auto;
         margin-top:8px;display:none;white-space:pre-wrap;word-break:break-all;
         font-family:'Fira Code','SF Mono',monospace}

/* ── Footer ── */
.ftr{text-align:center;padding:40px 0 20px;color:var(--muted);font-size:.75rem}
.ftr a{color:var(--accent);text-decoration:none;font-weight:700}

::-webkit-scrollbar{width:5px;height:5px}
::-webkit-scrollbar-track{background:#f0f9ff}
::-webkit-scrollbar-thumb{background:var(--border);border-radius:10px}

@media(max-width:620px){
  .hero h1{font-size:1.9rem}
  .hdr-r{display:none}
  .tabs{gap:3px}
  .tab{padding:7px 9px;font-size:.7rem}
  .ep-dsc{display:none}
}
</style>
</head>
<body>

<div class="hdr">
  <div class="hdr-in">
    <div class="logo">
      <div class="logo-ic">⚡</div>
      <div class="logo-tx">NEXUS<span>DEV</span> <small>API</small></div>
    </div>
    <div class="hdr-r">
      <span class="badge bl">● LIVE</span>
      <span class="badge bv">v4.1</span>
      <div class="key-pill">🔑 <span>${auth || 'not set'}</span></div>
    </div>
  </div>
</div>

<div class="wrap">

<div class="hero">
  <div class="hero-tag">⚡ REST API · HTTPS · Zero Port</div>
  <h1><span class="gr">NEXUSDEV</span><br>VPN Manager API</h1>
  <p>Kelola akun SSH, VMess, VLess &amp; Trojan via REST API.<br>Create · Trial · Renew · Delete — semua via HTTPS.</p>
  <div class="base-box">
    <span class="lbl">Base URL</span>
    <span class="val">${baseUrl}</span>
  </div>
</div>

<div class="stats">
  <div class="stat st1"><div class="stat-n">3</div><div class="stat-l">SSH</div></div>
  <div class="stat st2"><div class="stat-n">3</div><div class="stat-l">VMESS</div></div>
  <div class="stat st3"><div class="stat-n">3</div><div class="stat-l">VLESS</div></div>
  <div class="stat st4"><div class="stat-n">3</div><div class="stat-l">TROJAN</div></div>
  <div class="stat st5"><div class="stat-n">4</div><div class="stat-l">DELETE</div></div>
  <div class="stat st6"><div class="stat-n">4</div><div class="stat-l">RENEW</div></div>
</div>

<div class="tabs">
  <div class="tab active" onclick="showTab('all',this)">🔷 Semua</div>
  <div class="tab ts"     onclick="showTab('ssh',this)">🟢 SSH</div>
  <div class="tab tv"     onclick="showTab('vmess',this)">🔵 VMess</div>
  <div class="tab tvl"    onclick="showTab('vless',this)">🟣 VLess</div>
  <div class="tab ttr"    onclick="showTab('trojan',this)">🔴 Trojan</div>
  <div class="tab tdl"    onclick="showTab('del',this)">🗑 Delete</div>
  <div class="tab trn"    onclick="showTab('ren',this)">🔄 Renew</div>
</div>

<div class="tc active" id="tab-all">

<!-- ═══ SSH ═══ -->
<div id="grp-ssh">
<div class="sh"><div class="sh-dot" style="background:var(--ssh)"></div><span class="sh-lbl">SSH / OPENVPN</span><div class="sh-line"></div></div>

<div class="ep"><div class="ep-hd" onclick="tog(this)">
  <span class="mth mg">GET</span>
  <span class="ep-path">/api/trial-ssh</span>
  <span class="ep-dsc">Trial SSH 60 menit</span>
  <div class="tags"><span class="tag tg-ssh">SSH</span><span class="tag tg-trial">TRIAL</span></div>
  <span class="chev">▼</span>
</div><div class="ep-bd">
  <table class="pt"><tr><th>Parameter</th><th>Status</th><th>Keterangan</th></tr>
  <tr><td>auth</td><td><span class="req">WAJIB</span></td><td>API auth key</td></tr></table>
  <div class="ul">ENDPOINT</div>
  <div class="ub"><button class="cp" onclick="cpUrl(this)">Copy</button>${baseUrl}/api/trial-ssh?auth=${auth}</div>
  <div class="rl">RESPONSE</div>
  <div class="rb"><span class="k">"username"</span>: <span class="s">"Trial64897"</span>, <span class="k">"password"</span>: <span class="s">"1"</span>, <span class="k">"expired"</span>: <span class="s">"60 Minutes"</span></div>
  <div class="try-sec"><div class="try-ttl">⚡ TRY IT</div>
    <button class="tr-btn tr-go" onclick="tryApi('${baseUrl}/api/trial-ssh?auth=${auth}',this,'o-tsh')">Run →</button>
    <div class="try-out" id="o-tsh"></div>
  </div>
</div></div>

<div class="ep"><div class="ep-hd" onclick="tog(this)">
  <span class="mth mg">GET</span>
  <span class="ep-path">/api/create-ssh <span class="pm">?user= &password= &exp= &limitip=</span></span>
  <span class="ep-dsc">Buat akun SSH</span>
  <div class="tags"><span class="tag tg-ssh">SSH</span></div>
  <span class="chev">▼</span>
</div><div class="ep-bd">
  <table class="pt"><tr><th>Parameter</th><th>Status</th><th>Keterangan</th></tr>
  <tr><td>auth</td><td><span class="req">WAJIB</span></td><td>API auth key</td></tr>
  <tr><td>user</td><td><span class="req">WAJIB</span></td><td>Username</td></tr>
  <tr><td>password</td><td><span class="req">WAJIB</span></td><td>Password</td></tr>
  <tr><td>exp</td><td><span class="req">WAJIB</span></td><td>Masa aktif (hari)</td></tr>
  <tr><td>limitip</td><td><span class="opt">OPSIONAL</span></td><td>Maks IP (default: 1)</td></tr></table>
  <div class="ul">ENDPOINT</div>
  <div class="ub"><button class="cp" onclick="cpUrl(this)">Copy</button>${baseUrl}/api/create-ssh?auth=${auth}&amp;user=myuser&amp;password=mypass&amp;exp=30&amp;limitip=2</div>
  <div class="rl">RESPONSE</div>
  <div class="rb"><span class="k">"username"</span>: <span class="s">"myuser"</span>, <span class="k">"host"</span>: <span class="s">"${domain}"</span>, <span class="k">"expired"</span>: <span class="s">"30 Days"</span>, <span class="k">"expiredDate"</span>: <span class="s">"04 Apr, 2026"</span></div>
  <div class="try-sec"><div class="try-ttl">⚡ TRY IT</div>
    <div class="try-ins">
      <input class="ti" id="cs-u" placeholder="username">
      <input class="ti" id="cs-p" placeholder="password">
      <input class="ti" id="cs-e" placeholder="exp (hari)" style="max-width:90px">
      <input class="ti" id="cs-l" placeholder="limitip" style="max-width:80px">
      <button class="tr-btn tr-go" onclick="tryApi(\`${baseUrl}/api/create-ssh?auth=${auth}&user=\${gi('cs-u')}&password=\${gi('cs-p')}&exp=\${gi('cs-e')||30}&limitip=\${gi('cs-l')||1}\`,this,'o-cs')">Run →</button>
    </div>
    <div class="try-out" id="o-cs"></div>
  </div>
</div></div>
</div><!-- /grp-ssh -->

<!-- ═══ VMess ═══ -->
<div id="grp-vmess">
<div class="sh"><div class="sh-dot" style="background:var(--vmess)"></div><span class="sh-lbl">VMESS (XRAY)</span><div class="sh-line"></div></div>

<div class="ep"><div class="ep-hd" onclick="tog(this)">
  <span class="mth mg">GET</span>
  <span class="ep-path">/api/trial-vmess</span>
  <span class="ep-dsc">Trial VMess 60 menit</span>
  <div class="tags"><span class="tag tg-vmess">VMESS</span><span class="tag tg-trial">TRIAL</span></div>
  <span class="chev">▼</span>
</div><div class="ep-bd">
  <table class="pt"><tr><th>Parameter</th><th>Status</th><th>Keterangan</th></tr>
  <tr><td>auth</td><td><span class="req">WAJIB</span></td><td>API auth key</td></tr></table>
  <div class="ul">ENDPOINT</div>
  <div class="ub"><button class="cp" onclick="cpUrl(this)">Copy</button>${baseUrl}/api/trial-vmess?auth=${auth}</div>
  <div class="rl">RESPONSE</div>
  <div class="rb"><span class="k">"user"</span>: <span class="s">"Trial1234"</span>, <span class="k">"uuid"</span>: <span class="s">"xxxx-xxxx"</span>, <span class="k">"ws_tls"</span>: <span class="s">"vmess://..."</span>, <span class="k">"expired"</span>: <span class="s">"60 minutes"</span></div>
  <div class="try-sec"><div class="try-ttl">⚡ TRY IT</div>
    <button class="tr-btn tr-go" onclick="tryApi('${baseUrl}/api/trial-vmess?auth=${auth}',this,'o-tvm')">Run →</button>
    <div class="try-out" id="o-tvm"></div>
  </div>
</div></div>

<div class="ep"><div class="ep-hd" onclick="tog(this)">
  <span class="mth mg">GET</span>
  <span class="ep-path">/api/create-vmess <span class="pm">?user= &quota= &limitip= &exp=</span></span>
  <span class="ep-dsc">Buat akun VMess</span>
  <div class="tags"><span class="tag tg-vmess">VMESS</span></div>
  <span class="chev">▼</span>
</div><div class="ep-bd">
  <table class="pt"><tr><th>Parameter</th><th>Status</th><th>Keterangan</th></tr>
  <tr><td>auth</td><td><span class="req">WAJIB</span></td><td>API auth key</td></tr>
  <tr><td>user</td><td><span class="req">WAJIB</span></td><td>Username</td></tr>
  <tr><td>exp</td><td><span class="req">WAJIB</span></td><td>Masa aktif (hari)</td></tr>
  <tr><td>quota</td><td><span class="opt">OPSIONAL</span></td><td>Kuota GB (0=unlimited)</td></tr>
  <tr><td>limitip</td><td><span class="opt">OPSIONAL</span></td><td>Maks IP (default: 1)</td></tr></table>
  <div class="ul">ENDPOINT</div>
  <div class="ub"><button class="cp" onclick="cpUrl(this)">Copy</button>${baseUrl}/api/create-vmess?auth=${auth}&amp;user=myuser&amp;quota=10&amp;limitip=1&amp;exp=30</div>
  <div class="rl">RESPONSE</div>
  <div class="rb"><span class="k">"user"</span>: <span class="s">"myuser"</span>, <span class="k">"uuid"</span>: <span class="s">"xxxx"</span>, <span class="k">"quota"</span>: <span class="s">"10 GB"</span>, <span class="k">"expired"</span>: <span class="s">"30 Days"</span>, <span class="k">"ws_tls"</span>: <span class="s">"vmess://..."</span></div>
  <div class="try-sec"><div class="try-ttl">⚡ TRY IT</div>
    <div class="try-ins">
      <input class="ti" id="cv-u" placeholder="username">
      <input class="ti" id="cv-e" placeholder="exp (hari)" style="max-width:90px">
      <input class="ti" id="cv-q" placeholder="quota GB" style="max-width:90px">
      <button class="tr-btn tr-go" onclick="tryApi(\`${baseUrl}/api/create-vmess?auth=${auth}&user=\${gi('cv-u')}&exp=\${gi('cv-e')||30}&quota=\${gi('cv-q')||0}\`,this,'o-cv')">Run →</button>
    </div>
    <div class="try-out" id="o-cv"></div>
  </div>
</div></div>
</div><!-- /grp-vmess -->

<!-- ═══ VLess ═══ -->
<div id="grp-vless">
<div class="sh"><div class="sh-dot" style="background:var(--vless)"></div><span class="sh-lbl">VLESS (XRAY)</span><div class="sh-line"></div></div>

<div class="ep"><div class="ep-hd" onclick="tog(this)">
  <span class="mth mg">GET</span>
  <span class="ep-path">/api/trial-vless</span>
  <span class="ep-dsc">Trial VLess 60 menit</span>
  <div class="tags"><span class="tag tg-vless">VLESS</span><span class="tag tg-trial">TRIAL</span></div>
  <span class="chev">▼</span>
</div><div class="ep-bd">
  <table class="pt"><tr><th>Parameter</th><th>Status</th><th>Keterangan</th></tr>
  <tr><td>auth</td><td><span class="req">WAJIB</span></td><td>API auth key</td></tr></table>
  <div class="ul">ENDPOINT</div>
  <div class="ub"><button class="cp" onclick="cpUrl(this)">Copy</button>${baseUrl}/api/trial-vless?auth=${auth}</div>
  <div class="rl">RESPONSE</div>
  <div class="rb"><span class="k">"user"</span>: <span class="s">"Trial6813"</span>, <span class="k">"uuid"</span>: <span class="s">"xxxx-xxxx"</span>, <span class="k">"ws_tls"</span>: <span class="s">"vless://..."</span>, <span class="k">"expired"</span>: <span class="s">"60 minutes"</span></div>
  <div class="try-sec"><div class="try-ttl">⚡ TRY IT</div>
    <button class="tr-btn tr-go" onclick="tryApi('${baseUrl}/api/trial-vless?auth=${auth}',this,'o-tvl')">Run →</button>
    <div class="try-out" id="o-tvl"></div>
  </div>
</div></div>

<div class="ep"><div class="ep-hd" onclick="tog(this)">
  <span class="mth mg">GET</span>
  <span class="ep-path">/api/create-vless <span class="pm">?user= &quota= &limitip= &exp=</span></span>
  <span class="ep-dsc">Buat akun VLess</span>
  <div class="tags"><span class="tag tg-vless">VLESS</span></div>
  <span class="chev">▼</span>
</div><div class="ep-bd">
  <table class="pt"><tr><th>Parameter</th><th>Status</th><th>Keterangan</th></tr>
  <tr><td>auth</td><td><span class="req">WAJIB</span></td><td>API auth key</td></tr>
  <tr><td>user</td><td><span class="req">WAJIB</span></td><td>Username</td></tr>
  <tr><td>exp</td><td><span class="req">WAJIB</span></td><td>Masa aktif (hari)</td></tr>
  <tr><td>quota</td><td><span class="opt">OPSIONAL</span></td><td>Kuota GB</td></tr>
  <tr><td>limitip</td><td><span class="opt">OPSIONAL</span></td><td>Maks IP</td></tr></table>
  <div class="ul">ENDPOINT</div>
  <div class="ub"><button class="cp" onclick="cpUrl(this)">Copy</button>${baseUrl}/api/create-vless?auth=${auth}&amp;user=myuser&amp;quota=10&amp;limitip=1&amp;exp=30</div>
  <div class="rl">RESPONSE</div>
  <div class="rb"><span class="k">"user"</span>: <span class="s">"myuser"</span>, <span class="k">"uuid"</span>: <span class="s">"xxxx"</span>, <span class="k">"ws_tls"</span>: <span class="s">"vless://..."</span>, <span class="k">"expired"</span>: <span class="s">"30 Days"</span></div>
  <div class="try-sec"><div class="try-ttl">⚡ TRY IT</div>
    <div class="try-ins">
      <input class="ti" id="cvl-u" placeholder="username">
      <input class="ti" id="cvl-e" placeholder="exp (hari)" style="max-width:90px">
      <input class="ti" id="cvl-q" placeholder="quota GB" style="max-width:90px">
      <button class="tr-btn tr-go" onclick="tryApi(\`${baseUrl}/api/create-vless?auth=${auth}&user=\${gi('cvl-u')}&exp=\${gi('cvl-e')||30}&quota=\${gi('cvl-q')||0}\`,this,'o-cvl')">Run →</button>
    </div>
    <div class="try-out" id="o-cvl"></div>
  </div>
</div></div>
</div><!-- /grp-vless -->

<!-- ═══ Trojan ═══ -->
<div id="grp-trojan">
<div class="sh"><div class="sh-dot" style="background:var(--trojan)"></div><span class="sh-lbl">TROJAN (XRAY)</span><div class="sh-line"></div></div>

<div class="ep"><div class="ep-hd" onclick="tog(this)">
  <span class="mth mg">GET</span>
  <span class="ep-path">/api/trial-trojan</span>
  <span class="ep-dsc">Trial Trojan 60 menit</span>
  <div class="tags"><span class="tag tg-trojan">TROJAN</span><span class="tag tg-trial">TRIAL</span></div>
  <span class="chev">▼</span>
</div><div class="ep-bd">
  <table class="pt"><tr><th>Parameter</th><th>Status</th><th>Keterangan</th></tr>
  <tr><td>auth</td><td><span class="req">WAJIB</span></td><td>API auth key</td></tr></table>
  <div class="ul">ENDPOINT</div>
  <div class="ub"><button class="cp" onclick="cpUrl(this)">Copy</button>${baseUrl}/api/trial-trojan?auth=${auth}</div>
  <div class="rl">RESPONSE</div>
  <div class="rb"><span class="k">"user"</span>: <span class="s">"Trial7804"</span>, <span class="k">"uuid"</span>: <span class="s">"xxxx-xxxx"</span>, <span class="k">"ws"</span>: <span class="s">"trojan://..."</span>, <span class="k">"expired"</span>: <span class="s">"60 minutes"</span></div>
  <div class="try-sec"><div class="try-ttl">⚡ TRY IT</div>
    <button class="tr-btn tr-go" onclick="tryApi('${baseUrl}/api/trial-trojan?auth=${auth}',this,'o-ttr')">Run →</button>
    <div class="try-out" id="o-ttr"></div>
  </div>
</div></div>

<div class="ep"><div class="ep-hd" onclick="tog(this)">
  <span class="mth mg">GET</span>
  <span class="ep-path">/api/create-trojan <span class="pm">?user= &quota= &limitip= &exp=</span></span>
  <span class="ep-dsc">Buat akun Trojan</span>
  <div class="tags"><span class="tag tg-trojan">TROJAN</span></div>
  <span class="chev">▼</span>
</div><div class="ep-bd">
  <table class="pt"><tr><th>Parameter</th><th>Status</th><th>Keterangan</th></tr>
  <tr><td>auth</td><td><span class="req">WAJIB</span></td><td>API auth key</td></tr>
  <tr><td>user</td><td><span class="req">WAJIB</span></td><td>Username</td></tr>
  <tr><td>exp</td><td><span class="req">WAJIB</span></td><td>Masa aktif (hari)</td></tr>
  <tr><td>quota</td><td><span class="opt">OPSIONAL</span></td><td>Kuota GB</td></tr>
  <tr><td>limitip</td><td><span class="opt">OPSIONAL</span></td><td>Maks IP</td></tr></table>
  <div class="ul">ENDPOINT</div>
  <div class="ub"><button class="cp" onclick="cpUrl(this)">Copy</button>${baseUrl}/api/create-trojan?auth=${auth}&amp;user=myuser&amp;quota=10&amp;limitip=1&amp;exp=30</div>
  <div class="rl">RESPONSE</div>
  <div class="rb"><span class="k">"user"</span>: <span class="s">"myuser"</span>, <span class="k">"uuid"</span>: <span class="s">"xxxx"</span>, <span class="k">"ws"</span>: <span class="s">"trojan://..."</span>, <span class="k">"expired"</span>: <span class="s">"30 Days"</span></div>
  <div class="try-sec"><div class="try-ttl">⚡ TRY IT</div>
    <div class="try-ins">
      <input class="ti" id="ct-u" placeholder="username">
      <input class="ti" id="ct-e" placeholder="exp (hari)" style="max-width:90px">
      <input class="ti" id="ct-q" placeholder="quota GB" style="max-width:90px">
      <button class="tr-btn tr-go" onclick="tryApi(\`${baseUrl}/api/create-trojan?auth=${auth}&user=\${gi('ct-u')}&exp=\${gi('ct-e')||30}&quota=\${gi('ct-q')||0}\`,this,'o-ct')">Run →</button>
    </div>
    <div class="try-out" id="o-ct"></div>
  </div>
</div></div>
</div><!-- /grp-trojan -->

<!-- ═══ DELETE ═══ -->
<div id="grp-del">
<div class="sh"><div class="sh-dot" style="background:var(--del)"></div><span class="sh-lbl">DELETE ACCOUNTS</span><div class="sh-line"></div></div>

<div class="ep"><div class="ep-hd" onclick="tog(this)">
  <span class="mth md">GET</span>
  <span class="ep-path">/api/delssh <span class="pm">?username=</span></span>
  <span class="ep-dsc">Hapus akun SSH</span>
  <div class="tags"><span class="tag tg-del">DELETE</span><span class="tag tg-ssh">SSH</span></div>
  <span class="chev">▼</span>
</div><div class="ep-bd">
  <table class="pt"><tr><th>Parameter</th><th>Status</th><th>Keterangan</th></tr>
  <tr><td>auth</td><td><span class="req">WAJIB</span></td><td>API auth key</td></tr>
  <tr><td>username</td><td><span class="req">WAJIB</span></td><td>Username yang dihapus</td></tr></table>
  <div class="ul">ENDPOINT</div>
  <div class="ub"><button class="cp" onclick="cpUrl(this)">Copy</button>${baseUrl}/api/delssh?auth=${auth}&amp;username=myuser</div>
  <div class="rl">RESPONSE</div>
  <div class="rb"><span class="k">"status"</span>: <span class="s">"success"</span>, <span class="k">"message"</span>: <span class="s">"SSH account myuser deleted successfully"</span></div>
  <div class="try-sec"><div class="try-ttl">⚡ TRY IT</div>
    <div class="try-ins">
      <input class="ti" id="ds-u" placeholder="username">
      <button class="tr-btn tr-del" onclick="tryApi(\`${baseUrl}/api/delssh?auth=${auth}&username=\${gi('ds-u')}\`,this,'o-ds')">Delete →</button>
    </div>
    <div class="try-out" id="o-ds"></div>
  </div>
</div></div>

<div class="ep"><div class="ep-hd" onclick="tog(this)">
  <span class="mth md">GET</span>
  <span class="ep-path">/api/delws <span class="pm">?username=</span></span>
  <span class="ep-dsc">Hapus akun VMess</span>
  <div class="tags"><span class="tag tg-del">DELETE</span><span class="tag tg-vmess">VMESS</span></div>
  <span class="chev">▼</span>
</div><div class="ep-bd">
  <table class="pt"><tr><th>Parameter</th><th>Status</th><th>Keterangan</th></tr>
  <tr><td>auth</td><td><span class="req">WAJIB</span></td><td>API auth key</td></tr>
  <tr><td>username</td><td><span class="req">WAJIB</span></td><td>Username yang dihapus</td></tr></table>
  <div class="ul">ENDPOINT</div>
  <div class="ub"><button class="cp" onclick="cpUrl(this)">Copy</button>${baseUrl}/api/delws?auth=${auth}&amp;username=myuser</div>
  <div class="rl">RESPONSE</div>
  <div class="rb"><span class="k">"status"</span>: <span class="s">"success"</span>, <span class="k">"message"</span>: <span class="s">"VMess account myuser deleted successfully"</span></div>
  <div class="try-sec"><div class="try-ttl">⚡ TRY IT</div>
    <div class="try-ins">
      <input class="ti" id="dv-u" placeholder="username">
      <button class="tr-btn tr-del" onclick="tryApi(\`${baseUrl}/api/delws?auth=${auth}&username=\${gi('dv-u')}\`,this,'o-dv')">Delete →</button>
    </div>
    <div class="try-out" id="o-dv"></div>
  </div>
</div></div>

<div class="ep"><div class="ep-hd" onclick="tog(this)">
  <span class="mth md">GET</span>
  <span class="ep-path">/api/delvl <span class="pm">?username=</span></span>
  <span class="ep-dsc">Hapus akun VLess</span>
  <div class="tags"><span class="tag tg-del">DELETE</span><span class="tag tg-vless">VLESS</span></div>
  <span class="chev">▼</span>
</div><div class="ep-bd">
  <table class="pt"><tr><th>Parameter</th><th>Status</th><th>Keterangan</th></tr>
  <tr><td>auth</td><td><span class="req">WAJIB</span></td><td>API auth key</td></tr>
  <tr><td>username</td><td><span class="req">WAJIB</span></td><td>Username yang dihapus</td></tr></table>
  <div class="ul">ENDPOINT</div>
  <div class="ub"><button class="cp" onclick="cpUrl(this)">Copy</button>${baseUrl}/api/delvl?auth=${auth}&amp;username=myuser</div>
  <div class="rl">RESPONSE</div>
  <div class="rb"><span class="k">"status"</span>: <span class="s">"success"</span>, <span class="k">"message"</span>: <span class="s">"VLess account myuser deleted successfully"</span></div>
  <div class="try-sec"><div class="try-ttl">⚡ TRY IT</div>
    <div class="try-ins">
      <input class="ti" id="dvl-u" placeholder="username">
      <button class="tr-btn tr-del" onclick="tryApi(\`${baseUrl}/api/delvl?auth=${auth}&username=\${gi('dvl-u')}\`,this,'o-dvl')">Delete →</button>
    </div>
    <div class="try-out" id="o-dvl"></div>
  </div>
</div></div>

<div class="ep"><div class="ep-hd" onclick="tog(this)">
  <span class="mth md">GET</span>
  <span class="ep-path">/api/deltr <span class="pm">?username=</span></span>
  <span class="ep-dsc">Hapus akun Trojan</span>
  <div class="tags"><span class="tag tg-del">DELETE</span><span class="tag tg-trojan">TROJAN</span></div>
  <span class="chev">▼</span>
</div><div class="ep-bd">
  <table class="pt"><tr><th>Parameter</th><th>Status</th><th>Keterangan</th></tr>
  <tr><td>auth</td><td><span class="req">WAJIB</span></td><td>API auth key</td></tr>
  <tr><td>username</td><td><span class="req">WAJIB</span></td><td>Username yang dihapus</td></tr></table>
  <div class="ul">ENDPOINT</div>
  <div class="ub"><button class="cp" onclick="cpUrl(this)">Copy</button>${baseUrl}/api/deltr?auth=${auth}&amp;username=myuser</div>
  <div class="rl">RESPONSE</div>
  <div class="rb"><span class="k">"status"</span>: <span class="s">"success"</span>, <span class="k">"message"</span>: <span class="s">"Trojan account myuser deleted successfully"</span></div>
  <div class="try-sec"><div class="try-ttl">⚡ TRY IT</div>
    <div class="try-ins">
      <input class="ti" id="dt-u" placeholder="username">
      <button class="tr-btn tr-del" onclick="tryApi(\`${baseUrl}/api/deltr?auth=${auth}&username=\${gi('dt-u')}\`,this,'o-dt')">Delete →</button>
    </div>
    <div class="try-out" id="o-dt"></div>
  </div>
</div></div>
</div><!-- /grp-del -->

<!-- ═══ RENEW ═══ -->
<div id="grp-ren">
<div class="sh"><div class="sh-dot" style="background:var(--ren)"></div><span class="sh-lbl">RENEW ACCOUNTS</span><div class="sh-line"></div></div>

<div class="ep"><div class="ep-hd" onclick="tog(this)">
  <span class="mth mr">GET</span>
  <span class="ep-path">/api/rensh <span class="pm">?num= &exp=</span></span>
  <span class="ep-dsc">Perpanjang akun SSH</span>
  <div class="tags"><span class="tag tg-ren">RENEW</span><span class="tag tg-ssh">SSH</span></div>
  <span class="chev">▼</span>
</div><div class="ep-bd">
  <table class="pt"><tr><th>Parameter</th><th>Status</th><th>Keterangan</th></tr>
  <tr><td>auth</td><td><span class="req">WAJIB</span></td><td>API auth key</td></tr>
  <tr><td>num</td><td><span class="req">WAJIB</span></td><td>Username akun SSH</td></tr>
  <tr><td>exp</td><td><span class="req">WAJIB</span></td><td>Jumlah hari perpanjangan</td></tr></table>
  <div class="ul">ENDPOINT</div>
  <div class="ub"><button class="cp" onclick="cpUrl(this)">Copy</button>${baseUrl}/api/rensh?auth=${auth}&amp;num=myuser&amp;exp=30</div>
  <div class="rl">RESPONSE</div>
  <div class="rb"><span class="k">"status"</span>: <span class="s">"success"</span>,<br><span class="k">"data"</span>: {<br>  <span class="k">"username"</span>: <span class="s">"myuser"</span>,<br>  <span class="k">"previous_expiry"</span>: <span class="s">"Mar 06, 2026"</span>,<br>  <span class="k">"days_added"</span>: <span class="n">30</span>,<br>  <span class="k">"expired"</span>: <span class="s">"2026-04-05"</span>,<br>  <span class="k">"new_expiry_display"</span>: <span class="s">"05 Apr, 2026"</span><br>}</div>
  <div class="try-sec"><div class="try-ttl">⚡ TRY IT</div>
    <div class="try-ins">
      <input class="ti" id="rsh-n" placeholder="username (num)">
      <input class="ti" id="rsh-e" placeholder="exp (hari)" style="max-width:100px">
      <button class="tr-btn tr-ren" onclick="tryApi(\`${baseUrl}/api/rensh?auth=${auth}&num=\${gi('rsh-n')}&exp=\${gi('rsh-e')||30}\`,this,'o-rsh')">Renew →</button>
    </div>
    <div class="try-out" id="o-rsh"></div>
  </div>
</div></div>

<div class="ep"><div class="ep-hd" onclick="tog(this)">
  <span class="mth mr">GET</span>
  <span class="ep-path">/api/renws <span class="pm">?num= &exp=</span></span>
  <span class="ep-dsc">Perpanjang akun VMess</span>
  <div class="tags"><span class="tag tg-ren">RENEW</span><span class="tag tg-vmess">VMESS</span></div>
  <span class="chev">▼</span>
</div><div class="ep-bd">
  <table class="pt"><tr><th>Parameter</th><th>Status</th><th>Keterangan</th></tr>
  <tr><td>auth</td><td><span class="req">WAJIB</span></td><td>API auth key</td></tr>
  <tr><td>num</td><td><span class="req">WAJIB</span></td><td>Username akun VMess</td></tr>
  <tr><td>exp</td><td><span class="req">WAJIB</span></td><td>Jumlah hari perpanjangan</td></tr></table>
  <div class="ul">ENDPOINT</div>
  <div class="ub"><button class="cp" onclick="cpUrl(this)">Copy</button>${baseUrl}/api/renws?auth=${auth}&amp;num=myuser&amp;exp=30</div>
  <div class="rl">RESPONSE</div>
  <div class="rb"><span class="k">"status"</span>: <span class="s">"success"</span>,<br><span class="k">"data"</span>: {<br>  <span class="k">"username"</span>: <span class="s">"gua12"</span>,<br>  <span class="k">"previous_expiry"</span>: <span class="s">"Mar 06, 2026"</span>,<br>  <span class="k">"days_added"</span>: <span class="n">1</span>,<br>  <span class="k">"expired"</span>: <span class="s">"2026-03-07"</span>,<br>  <span class="k">"main_updated"</span>: <span class="b">true</span>,<br>  <span class="k">"grpc_updated"</span>: <span class="b">false</span><br>}</div>
  <div class="try-sec"><div class="try-ttl">⚡ TRY IT</div>
    <div class="try-ins">
      <input class="ti" id="rws-n" placeholder="username (num)">
      <input class="ti" id="rws-e" placeholder="exp (hari)" style="max-width:100px">
      <button class="tr-btn tr-ren" onclick="tryApi(\`${baseUrl}/api/renws?auth=${auth}&num=\${gi('rws-n')}&exp=\${gi('rws-e')||30}\`,this,'o-rws')">Renew →</button>
    </div>
    <div class="try-out" id="o-rws"></div>
  </div>
</div></div>

<div class="ep"><div class="ep-hd" onclick="tog(this)">
  <span class="mth mr">GET</span>
  <span class="ep-path">/api/renvl <span class="pm">?num= &exp=</span></span>
  <span class="ep-dsc">Perpanjang akun VLess</span>
  <div class="tags"><span class="tag tg-ren">RENEW</span><span class="tag tg-vless">VLESS</span></div>
  <span class="chev">▼</span>
</div><div class="ep-bd">
  <table class="pt"><tr><th>Parameter</th><th>Status</th><th>Keterangan</th></tr>
  <tr><td>auth</td><td><span class="req">WAJIB</span></td><td>API auth key</td></tr>
  <tr><td>num</td><td><span class="req">WAJIB</span></td><td>Username akun VLess</td></tr>
  <tr><td>exp</td><td><span class="req">WAJIB</span></td><td>Jumlah hari perpanjangan</td></tr></table>
  <div class="ul">ENDPOINT</div>
  <div class="ub"><button class="cp" onclick="cpUrl(this)">Copy</button>${baseUrl}/api/renvl?auth=${auth}&amp;num=myuser&amp;exp=30</div>
  <div class="rl">RESPONSE</div>
  <div class="rb"><span class="k">"status"</span>: <span class="s">"success"</span>,<br><span class="k">"data"</span>: {<br>  <span class="k">"username"</span>: <span class="s">"gua12"</span>,<br>  <span class="k">"previous_expiry"</span>: <span class="s">"Mar 06, 2026"</span>,<br>  <span class="k">"days_added"</span>: <span class="n">1</span>,<br>  <span class="k">"expired"</span>: <span class="s">"2026-03-07"</span>,<br>  <span class="k">"main_updated"</span>: <span class="b">true</span>,<br>  <span class="k">"grpc_updated"</span>: <span class="b">false</span><br>}</div>
  <div class="try-sec"><div class="try-ttl">⚡ TRY IT</div>
    <div class="try-ins">
      <input class="ti" id="rvl-n" placeholder="username (num)">
      <input class="ti" id="rvl-e" placeholder="exp (hari)" style="max-width:100px">
      <button class="tr-btn tr-ren" onclick="tryApi(\`${baseUrl}/api/renvl?auth=${auth}&num=\${gi('rvl-n')}&exp=\${gi('rvl-e')||30}\`,this,'o-rvl')">Renew →</button>
    </div>
    <div class="try-out" id="o-rvl"></div>
  </div>
</div></div>

<div class="ep"><div class="ep-hd" onclick="tog(this)">
  <span class="mth mr">GET</span>
  <span class="ep-path">/api/rentr <span class="pm">?num= &exp=</span></span>
  <span class="ep-dsc">Perpanjang akun Trojan</span>
  <div class="tags"><span class="tag tg-ren">RENEW</span><span class="tag tg-trojan">TROJAN</span></div>
  <span class="chev">▼</span>
</div><div class="ep-bd">
  <table class="pt"><tr><th>Parameter</th><th>Status</th><th>Keterangan</th></tr>
  <tr><td>auth</td><td><span class="req">WAJIB</span></td><td>API auth key</td></tr>
  <tr><td>num</td><td><span class="req">WAJIB</span></td><td>Username akun Trojan</td></tr>
  <tr><td>exp</td><td><span class="req">WAJIB</span></td><td>Jumlah hari perpanjangan</td></tr></table>
  <div class="ul">ENDPOINT</div>
  <div class="ub"><button class="cp" onclick="cpUrl(this)">Copy</button>${baseUrl}/api/rentr?auth=${auth}&amp;num=myuser&amp;exp=30</div>
  <div class="rl">RESPONSE</div>
  <div class="rb"><span class="k">"status"</span>: <span class="s">"success"</span>,<br><span class="k">"data"</span>: {<br>  <span class="k">"username"</span>: <span class="s">"gua12"</span>,<br>  <span class="k">"previous_expiry"</span>: <span class="s">"Mar 06, 2026"</span>,<br>  <span class="k">"days_added"</span>: <span class="n">1</span>,<br>  <span class="k">"expired"</span>: <span class="s">"2026-03-07"</span>,<br>  <span class="k">"main_updated"</span>: <span class="b">true</span>,<br>  <span class="k">"grpc_updated"</span>: <span class="b">false</span><br>}</div>
  <div class="try-sec"><div class="try-ttl">⚡ TRY IT</div>
    <div class="try-ins">
      <input class="ti" id="rtr-n" placeholder="username (num)">
      <input class="ti" id="rtr-e" placeholder="exp (hari)" style="max-width:100px">
      <button class="tr-btn tr-ren" onclick="tryApi(\`${baseUrl}/api/rentr?auth=${auth}&num=\${gi('rtr-n')}&exp=\${gi('rtr-e')||30}\`,this,'o-rtr')">Renew →</button>
    </div>
    <div class="try-out" id="o-rtr"></div>
  </div>
</div></div>
</div><!-- /grp-ren -->

</div><!-- /tab-all -->

<div class="ftr">⚡ NEXUSDEV API · HTTPS via Nginx · <a href="https://t.me/nexusdev">@nexusdev</a></div>
</div>

<script>
function gi(id){return document.getElementById(id)?.value?.trim()||''}
function tog(hd){
  const bd=hd.nextElementSibling;
  const open=bd.classList.toggle('open');
  hd.querySelector('.chev').style.transform=open?'rotate(180deg)':'rotate(0deg)';
}
function cpUrl(btn){
  const t=btn.parentElement.textContent.replace('Copy','').trim();
  navigator.clipboard.writeText(t).then(()=>{
    btn.textContent='✓ OK';btn.classList.add('ok');
    setTimeout(()=>{btn.textContent='Copy';btn.classList.remove('ok')},1800);
  });
}
async function tryApi(url,btn,outId){
  const out=document.getElementById(outId);
  if(!out)return;
  const orig=btn.textContent;
  btn.textContent='...';btn.disabled=true;
  out.style.display='block';out.textContent='⏳ Loading...';
  try{
    const r=await fetch(url);
    const j=await r.json();
    out.textContent=JSON.stringify(j,null,2);
  }catch(e){out.textContent='❌ '+e.message;}
  btn.textContent=orig;btn.disabled=false;
}
function showTab(name,el){
  document.querySelectorAll('.tabs .tab').forEach(t=>t.classList.remove('active'));
  el.classList.add('active');
  document.getElementById('tab-all').classList.add('active');
  ['ssh','vmess','vless','trojan','del','ren'].forEach(g=>{
    const e=document.getElementById('grp-'+g);
    if(e) e.style.display=(name==='all'||name===g)?'':'none';
  });
}
</script>
</body></html>`;
  sendHTML(res, html);
}



// ─── Delete SSH ───────────────────────────────────────────────────────────────
function handleDeleteSSH(params, res) {
  const username = params.username || params.user;
  if (!username) return sendJSON(res, 400, { status:'error', message:'Required: username' });
  const exists = execCmd(`id "${username}" 2>/dev/null`);
  if (!exists.ok) return sendJSON(res, 404, { status:'error', message:`SSH account ${username} not found` });
  execCmd(`userdel -f "${username}" 2>/dev/null || true`);
  execCmd(`sed -i '/^${username}:/d' /etc/group 2>/dev/null || true`);
  execCmd(`grep -wE "^#ssh# ${username}" /etc/ssh/.ssh.db | awk '{print $1" "$2" "$3}' | sort | uniq | tail -1 >> /etc/xray/.userall.db 2>/dev/null || true`);
  execCmd(`sed -i "/^#ssh# ${username}/d" /etc/ssh/.ssh.db 2>/dev/null || true`);
  execCmd(`rm -f /etc/ssh/${username} /etc/kyt/limit/ssh/ip/${username} /var/www/html/ssh-${username}.txt`);
  sendJSON(res, 200, { status:'success', message:`SSH account ${username} deleted successfully` });
}

// ─── Delete VMess ─────────────────────────────────────────────────────────────
function handleDeleteVmess(params, res) {
  const username = params.username || params.user;
  if (!username) return sendJSON(res, 400, { status:'error', message:'Required: username' });
  const inDb = execCmd(`grep -w "^### ${username} " /etc/vmess/.vmess.db 2>/dev/null`);
  if (!inDb.out.trim()) return sendJSON(res, 404, { status:'error', message:`VMess account ${username} not found` });
  execCmd(`sed -i "/### ${username} /d" /etc/xray/config.json 2>/dev/null || true`);
  execCmd(`sed -i "/{.*\\"email\\".*\\"${username}\\".*/d" /etc/xray/config.json 2>/dev/null || true`);
  execCmd(`sed -i "/^### ${username}/d" /etc/vmess/.vmess.db 2>/dev/null || true`);
  execCmd(`rm -f /etc/vmess/${username} /etc/kyt/limit/vmess/ip/${username} /var/www/html/vmess-${username}.txt`);
  execCmd(`systemctl restart xray 2>/dev/null || true`);
  sendJSON(res, 200, { status:'success', message:`VMess account ${username} deleted successfully` });
}

// ─── Delete VLess ─────────────────────────────────────────────────────────────
function handleDeleteVless(params, res) {
  const username = params.username || params.user;
  if (!username) return sendJSON(res, 400, { status:'error', message:'Required: username' });
  const inDb = execCmd(`grep -w "^#& ${username} " /etc/vless/.vless.db 2>/dev/null`);
  if (!inDb.out.trim()) return sendJSON(res, 404, { status:'error', message:`VLess account ${username} not found` });
  execCmd(`sed -i "/#& ${username} /d" /etc/xray/config.json 2>/dev/null || true`);
  execCmd(`sed -i "/{.*\\"email\\".*\\"${username}\\".*/d" /etc/xray/config.json 2>/dev/null || true`);
  execCmd(`sed -i "/^#& ${username}/d" /etc/vless/.vless.db 2>/dev/null || true`);
  execCmd(`rm -f /etc/vless/${username} /etc/kyt/limit/vless/ip/${username} /var/www/html/vless-${username}.txt`);
  execCmd(`systemctl restart xray 2>/dev/null || true`);
  sendJSON(res, 200, { status:'success', message:`VLess account ${username} deleted successfully` });
}

// ─── Delete Trojan ────────────────────────────────────────────────────────────
function handleDeleteTrojan(params, res) {
  const username = params.username || params.user;
  if (!username) return sendJSON(res, 400, { status:'error', message:'Required: username' });
  const inDb = execCmd(`grep -w "^### ${username} " /etc/trojan/.trojan.db 2>/dev/null`);
  if (!inDb.out.trim()) return sendJSON(res, 404, { status:'error', message:`Trojan account ${username} not found` });
  execCmd(`sed -i "/#! ${username} /d" /etc/xray/config.json 2>/dev/null || true`);
  execCmd(`sed -i "/{.*\\"email\\".*\\"${username}\\".*/d" /etc/xray/config.json 2>/dev/null || true`);
  execCmd(`sed -i "/^### ${username}/d" /etc/trojan/.trojan.db 2>/dev/null || true`);
  execCmd(`rm -f /etc/trojan/${username} /etc/kyt/limit/trojan/ip/${username} /var/www/html/trojan-${username}.txt`);
  execCmd(`systemctl restart xray 2>/dev/null || true`);
  sendJSON(res, 200, { status:'success', message:`Trojan account ${username} deleted successfully` });
}

// ─── Renew SSH ────────────────────────────────────────────────────────────────
// ─── Helper: safe file line-replace using Node.js fs (no shell sed) ──────────
function fileReplaceLines(filePath, matchFn, replaceFn) {
  // Returns { ok, linesChanged }
  try {
    const raw   = fs.readFileSync(filePath, 'utf8');
    let changed = 0;
    const out   = raw.split('\n').map(line => {
      if (matchFn(line)) { changed++; return replaceFn(line); }
      return line;
    }).join('\n');
    if (changed > 0) fs.writeFileSync(filePath, out, 'utf8');
    return { ok: true, linesChanged: changed };
  } catch { return { ok: false, linesChanged: 0 }; }
}

// ─── Helper: find line and extract 3rd token (date field) ────────────────────
function fileGetExpiry(filePath, matchFn) {
  try {
    const raw  = fs.readFileSync(filePath, 'utf8');
    const line = raw.split('\n').find(l => matchFn(l)) || '';
    return line.trim().split(/\s+/)[2] || '';   // index 2 = YYYY-MM-DD
  } catch { return ''; }
}

// ─── Helper: calculate new expiry (extend from current or today if expired) ──
function calcNewExpiry(curExpStr, days) {
  let base = curExpStr ? new Date(curExpStr + 'T00:00:00') : new Date();
  const now = new Date(); now.setHours(0, 0, 0, 0);
  if (isNaN(base.getTime()) || base < now) base = new Date(now);
  base.setDate(base.getDate() + days);
  return base;
}

// ─── Renew SSH ────────────────────────────────────────────────────────────────
function handleRenewSSH(params, res) {
  try {
    const username = params.num || params.username || params.user;
    const exp      = params.exp;
    if (!username || !exp)
      return sendJSON(res, 400, { status: 'error', message: 'Required: num (username), exp (days)' });

    const days = parseInt(exp);
    if (isNaN(days) || days < 1)
      return sendJSON(res, 400, { status: 'error', message: 'exp must be a positive integer (days)' });

    // Validate user exists
    const exists = execCmd(`id "${username}" 2>/dev/null`);
    if (!exists.ok)
      return sendJSON(res, 404, { status: 'error', message: `SSH account ${username} not found` });

    // Read previous expiry from .ssh.db — line format: #ssh# USER PASS 0 LIMITIP DD Mon, YYYY
    const SSH_DB = '/etc/ssh/.ssh.db';
    let prevExp = 'unknown';
    try {
      const dbLine = fs.readFileSync(SSH_DB, 'utf8').split('\n')
        .find(l => l.startsWith(`#ssh# ${username} `)) || '';
      const parts = dbLine.trim().split(/\s+/);
      // parts: [#ssh#, user, pass, 0, limitip, DD, Mon,, YYYY]
      prevExp = parts.slice(5).join(' ').replace(/,$/, '').trim() || 'unknown';
    } catch {}

    const newExpDate = calcNewExpiry('', days); // SSH always extends from today
    const newExpISO  = newExpDate.toISOString().split('T')[0];
    const newExpStr  = formatDateShort(newExpDate);

    // Update system account
    execCmd(`usermod -e "${newExpISO}" "${username}" 2>/dev/null || true`);
    execCmd(`passwd -u "${username}" 2>/dev/null || true`);

    // Update .ssh.db using fs (no shell sed with special chars)
    fileReplaceLines(SSH_DB,
      l => l.startsWith(`#ssh# ${username} `),
      l => {
        const p = l.trim().split(/\s+/);
        // keep: #ssh# user pass 0 limitip — replace exp
        const keep = p.slice(0, 5).join(' ');
        return `${keep} ${newExpStr}`;
      }
    );

    execCmd(`rm -f /etc/kyt/limit/ssh/ip/${username} 2>/dev/null || true`);

    sendJSON(res, 200, {
      status: 'success',
      data: { username, previous_expiry: prevExp, days_added: days, expired: newExpISO, new_expiry_display: newExpStr }
    });
  } catch (e) {
    sendJSON(res, 500, { status: 'error', message: e.message });
  }
}

// ─── Renew VMess ──────────────────────────────────────────────────────────────
function handleRenewVmess(params, res) {
  try {
    const username = params.num || params.username || params.user;
    const exp      = params.exp;
    if (!username || !exp)
      return sendJSON(res, 400, { status: 'error', message: 'Required: num (username), exp (days)' });

    const days = parseInt(exp);
    if (isNaN(days) || days < 1)
      return sendJSON(res, 400, { status: 'error', message: 'exp must be a positive integer (days)' });

    const CFG_JSON = '/etc/xray/config.json';
    const VMESS_DB = '/etc/vmess/.vmess.db';

    // Find current expiry — line format: ### username YYYY-MM-DD
    const curExpStr = fileGetExpiry(CFG_JSON, l => l.startsWith(`### ${username} `));
    if (!curExpStr)
      return sendJSON(res, 404, { status: 'error', message: `VMess account ${username} not found` });

    const prevExp   = formatDateShort(new Date(curExpStr + 'T00:00:00'));
    const newExpDate = calcNewExpiry(curExpStr, days);
    const newExpISO  = newExpDate.toISOString().split('T')[0];
    const newExpStr  = formatDateShort(newExpDate);

    // Update config.json — replace ALL "### username YYYY-MM-DD" lines (ws + grpc)
    const cfgResult = fileReplaceLines(CFG_JSON,
      l => l.startsWith(`### ${username} `),
      () => `### ${username} ${newExpISO}`
    );

    // Update .vmess.db — line format: ### username YYYY-MM-DD uuid quota limitip
    fileReplaceLines(VMESS_DB,
      l => l.startsWith(`### ${username} `),
      l => {
        const p = l.trim().split(/\s+/);
        // replace date (index 2), keep rest
        p[2] = newExpISO;
        return p.join(' ');
      }
    );

    execCmd('systemctl restart xray 2>/dev/null || true');

    sendJSON(res, 200, {
      status: 'success',
      data: {
        username, previous_expiry: prevExp, days_added: days,
        expired: newExpISO, new_expiry_display: newExpStr,
        main_updated: cfgResult.linesChanged > 0,
        grpc_updated: cfgResult.linesChanged > 1
      }
    });
  } catch (e) {
    sendJSON(res, 500, { status: 'error', message: e.message });
  }
}

// ─── Renew VLess ──────────────────────────────────────────────────────────────
function handleRenewVless(params, res) {
  try {
    const username = params.num || params.username || params.user;
    const exp      = params.exp;
    if (!username || !exp)
      return sendJSON(res, 400, { status: 'error', message: 'Required: num (username), exp (days)' });

    const days = parseInt(exp);
    if (isNaN(days) || days < 1)
      return sendJSON(res, 400, { status: 'error', message: 'exp must be a positive integer (days)' });

    const CFG_JSON = '/etc/xray/config.json';
    const VLESS_DB = '/etc/vless/.vless.db';

    // VLess lines: #& username YYYY-MM-DD
    const curExpStr = fileGetExpiry(CFG_JSON, l => l.startsWith(`#& ${username} `));
    if (!curExpStr)
      return sendJSON(res, 404, { status: 'error', message: `VLess account ${username} not found` });

    const prevExp    = formatDateShort(new Date(curExpStr + 'T00:00:00'));
    const newExpDate = calcNewExpiry(curExpStr, days);
    const newExpISO  = newExpDate.toISOString().split('T')[0];
    const newExpStr  = formatDateShort(newExpDate);

    const cfgResult = fileReplaceLines(CFG_JSON,
      l => l.startsWith(`#& ${username} `),
      () => `#& ${username} ${newExpISO}`
    );

    fileReplaceLines(VLESS_DB,
      l => l.startsWith(`#& ${username} `),
      l => { const p = l.trim().split(/\s+/); p[2] = newExpISO; return p.join(' '); }
    );

    execCmd('systemctl restart xray 2>/dev/null || true');

    sendJSON(res, 200, {
      status: 'success',
      data: {
        username, previous_expiry: prevExp, days_added: days,
        expired: newExpISO, new_expiry_display: newExpStr,
        main_updated: cfgResult.linesChanged > 0,
        grpc_updated: cfgResult.linesChanged > 1
      }
    });
  } catch (e) {
    sendJSON(res, 500, { status: 'error', message: e.message });
  }
}

// ─── Renew Trojan ─────────────────────────────────────────────────────────────
function handleRenewTrojan(params, res) {
  try {
    const username = params.num || params.username || params.user;
    const exp      = params.exp;
    if (!username || !exp)
      return sendJSON(res, 400, { status: 'error', message: 'Required: num (username), exp (days)' });

    const days = parseInt(exp);
    if (isNaN(days) || days < 1)
      return sendJSON(res, 400, { status: 'error', message: 'exp must be a positive integer (days)' });

    const CFG_JSON  = '/etc/xray/config.json';
    const TROJAN_DB = '/etc/trojan/.trojan.db';

    // Trojan lines: #! username YYYY-MM-DD
    const curExpStr = fileGetExpiry(CFG_JSON, l => l.startsWith(`#! ${username} `));
    if (!curExpStr)
      return sendJSON(res, 404, { status: 'error', message: `Trojan account ${username} not found` });

    const prevExp    = formatDateShort(new Date(curExpStr + 'T00:00:00'));
    const newExpDate = calcNewExpiry(curExpStr, days);
    const newExpISO  = newExpDate.toISOString().split('T')[0];
    const newExpStr  = formatDateShort(newExpDate);

    const cfgResult = fileReplaceLines(CFG_JSON,
      l => l.startsWith(`#! ${username} `),
      () => `#! ${username} ${newExpISO}`
    );

    fileReplaceLines(TROJAN_DB,
      l => l.startsWith(`#! ${username} `),
      l => { const p = l.trim().split(/\s+/); p[2] = newExpISO; return p.join(' '); }
    );

    execCmd('systemctl restart xray 2>/dev/null || true');

    sendJSON(res, 200, {
      status: 'success',
      data: {
        username, previous_expiry: prevExp, days_added: days,
        expired: newExpISO, new_expiry_display: newExpStr,
        main_updated: cfgResult.linesChanged > 0,
        grpc_updated: cfgResult.linesChanged > 1
      }
    });
  } catch (e) {
    sendJSON(res, 500, { status: 'error', message: e.message });
  }
}

// ─── Server & Router ─────────────────────────────────────────────────────────

const server = http.createServer((req, res) => {
  const parsed   = url.parse(req.url, true);
  const pathname = parsed.pathname;
  const params   = parsed.query;

  // Doc page — butuh auth
  if (pathname === '/api/doc.html') return handleDocPage(params, res);

  // Auth check
  if (pathname.startsWith('/api/')) {
    const stored = getAuth();
    if (stored && params.auth !== stored)
      return sendJSON(res, 403, { status: 'error', message: 'Invalid or missing auth key' });
  }

  // Create routes
  if (pathname === '/api/trial-ssh')     return handleTrialSSH(params, res);
  if (pathname === '/api/create-ssh')    return handleCreateSSH(params, res);
  if (pathname === '/api/trial-vmess')   return handleTrialVmess(params, res);
  if (pathname === '/api/create-vmess')  return handleCreateVmess(params, res);
  if (pathname === '/api/trial-vless')   return handleTrialVless(params, res);
  if (pathname === '/api/create-vless')  return handleCreateVless(params, res);
  if (pathname === '/api/trial-trojan')  return handleTrialTrojan(params, res);
  if (pathname === '/api/create-trojan') return handleCreateTrojan(params, res);

  // Delete routes
  if (pathname === '/api/delssh')  return handleDeleteSSH(params, res);
  if (pathname === '/api/delws')   return handleDeleteVmess(params, res);
  if (pathname === '/api/delvl')   return handleDeleteVless(params, res);
  if (pathname === '/api/deltr')   return handleDeleteTrojan(params, res);

  // Renew routes
  if (pathname === '/api/rensh')   return handleRenewSSH(params, res);
  if (pathname === '/api/renws')   return handleRenewVmess(params, res);
  if (pathname === '/api/renvl')   return handleRenewVless(params, res);
  if (pathname === '/api/rentr')   return handleRenewTrojan(params, res);

  sendJSON(res, 404, { status: 'error', message: `Not found: ${pathname} — see /api/doc.html` });
});

server.listen(PORT, HOST, () => {
  console.log(`[NEXUSDEV API] Listening on ${HOST}:${PORT}`);
  console.log(`[NEXUSDEV API] Proxied via Nginx → https://${getDomain()}/api/`);
});
