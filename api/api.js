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
body{font-family:'Segoe UI',sans-serif;background:#0d1117;color:#e6edf3;min-height:100vh;display:flex;align-items:center;justify-content:center}
.card{background:#161b22;border:1px solid #30363d;border-radius:14px;padding:40px 36px;width:100%;max-width:400px;text-align:center}
.logo{font-size:2.5rem;margin-bottom:10px}
h1{color:#58a6ff;font-size:1.3rem;margin-bottom:6px}
p{color:#8b949e;font-size:.83rem;margin-bottom:28px;line-height:1.5}
input{width:100%;background:#0d1117;border:1px solid #30363d;border-radius:8px;padding:11px 14px;color:#e6edf3;font-size:.95rem;outline:none;margin-bottom:14px;transition:border .2s}
input:focus{border-color:#58a6ff}
button{width:100%;background:#238636;border:none;border-radius:8px;padding:11px;color:#fff;font-size:.95rem;font-weight:700;cursor:pointer;transition:background .2s}
button:hover{background:#2ea043}
</style>
</head>
<body>
<div class="card">
  <div class="logo">⚡</div>
  <h1>NEXUSDEV API</h1>
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

  // Auth check untuk doc page
  if (auth && params.auth !== auth) {
    return handleDocLogin(res, domain);
  }

  const html = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1.0">
<title>NEXUSDEV API Docs</title>
<style>
:root{
  --bg:#0a0e1a;--panel:#0f1525;--card:#131929;--border:#1e2d4a;--border2:#243354;
  --accent:#00d4ff;--accent2:#7c3aed;--accent3:#10b981;--accent4:#f59e0b;--accent5:#ef4444;
  --text:#e2e8f0;--muted:#64748b;--muted2:#94a3b8;
  --ssh:#10b981;--vmess:#3b82f6;--vless:#8b5cf6;--trojan:#f43f5e;--trial:#f59e0b;--del:#ef4444;
}
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:'SF Mono','Fira Code','Consolas',monospace;background:var(--bg);color:var(--text);min-height:100vh;overflow-x:hidden}
/* Animated background */
body::before{content:'';position:fixed;inset:0;background:radial-gradient(ellipse at 20% 50%,#0d2137 0%,transparent 60%),radial-gradient(ellipse at 80% 20%,#1a0d37 0%,transparent 60%);pointer-events:none;z-index:0}
.wrap{position:relative;z-index:1;max-width:1100px;margin:0 auto;padding:0 16px 60px}

/* Header */
.hdr{background:linear-gradient(135deg,#0f1525 0%,#131929 100%);border-bottom:1px solid var(--border);padding:0 24px;position:sticky;top:0;z-index:100;backdrop-filter:blur(12px)}
.hdr-inner{max-width:1100px;margin:0 auto;height:60px;display:flex;align-items:center;justify-content:space-between;gap:16px}
.logo{display:flex;align-items:center;gap:10px}
.logo-icon{width:34px;height:34px;background:linear-gradient(135deg,var(--accent),var(--accent2));border-radius:8px;display:flex;align-items:center;justify-content:center;font-size:1rem;flex-shrink:0}
.logo-text{font-size:1rem;font-weight:700;color:var(--text);letter-spacing:.05em}
.logo-text span{color:var(--accent)}
.hdr-right{display:flex;align-items:center;gap:10px;flex-wrap:wrap}
.badge{padding:3px 10px;border-radius:20px;font-size:.68rem;font-weight:700;letter-spacing:.05em}
.badge-live{background:rgba(16,185,129,.15);color:var(--accent3);border:1px solid rgba(16,185,129,.3)}
.badge-ver{background:rgba(0,212,255,.1);color:var(--accent);border:1px solid rgba(0,212,255,.2)}
.key-pill{background:rgba(245,158,11,.08);border:1px solid rgba(245,158,11,.2);border-radius:6px;padding:4px 10px;font-size:.72rem;color:var(--accent4);display:flex;align-items:center;gap:6px;max-width:200px;overflow:hidden}
.key-pill span{overflow:hidden;text-overflow:ellipsis;white-space:nowrap}

/* Hero */
.hero{padding:48px 0 36px;text-align:center}
.hero-tag{display:inline-flex;align-items:center;gap:6px;background:rgba(0,212,255,.08);border:1px solid rgba(0,212,255,.2);border-radius:20px;padding:5px 14px;font-size:.72rem;color:var(--accent);letter-spacing:.08em;margin-bottom:20px}
.hero h1{font-size:2.4rem;font-weight:800;letter-spacing:-.02em;margin-bottom:12px;line-height:1.1}
.hero h1 .gr{background:linear-gradient(135deg,var(--accent),var(--accent2));-webkit-background-clip:text;-webkit-text-fill-color:transparent}
.hero p{color:var(--muted2);font-size:.9rem;max-width:520px;margin:0 auto 28px;font-family:'Segoe UI',sans-serif;line-height:1.6}
.base-url{display:inline-flex;align-items:center;gap:8px;background:var(--card);border:1px solid var(--border2);border-radius:8px;padding:8px 16px;font-size:.82rem}
.base-url .label{color:var(--muted);font-family:'Segoe UI',sans-serif}
.base-url .val{color:var(--accent)}

/* Stats bar */
.stats{display:grid;grid-template-columns:repeat(auto-fit,minmax(140px,1fr));gap:12px;margin:32px 0}
.stat{background:var(--card);border:1px solid var(--border);border-radius:10px;padding:16px;text-align:center;position:relative;overflow:hidden}
.stat::before{content:'';position:absolute;top:0;left:0;right:0;height:2px}
.stat.s1::before{background:var(--ssh)}
.stat.s2::before{background:var(--vmess)}
.stat.s3::before{background:var(--vless)}
.stat.s4::before{background:var(--trojan)}
.stat.s5::before{background:var(--del)}
.stat-num{font-size:1.6rem;font-weight:800;margin-bottom:4px}
.stat.s1 .stat-num{color:var(--ssh)}
.stat.s2 .stat-num{color:var(--vmess)}
.stat.s3 .stat-num{color:var(--vless)}
.stat.s4 .stat-num{color:var(--trojan)}
.stat.s5 .stat-num{color:var(--del)}
.stat-lbl{font-size:.7rem;color:var(--muted);letter-spacing:.05em;font-family:'Segoe UI',sans-serif}

/* Tabs */
.tabs{display:flex;gap:6px;flex-wrap:wrap;margin:32px 0 20px;border-bottom:1px solid var(--border);padding-bottom:0}
.tab{padding:9px 18px;border-radius:8px 8px 0 0;font-size:.78rem;font-weight:600;cursor:pointer;border:1px solid transparent;border-bottom:none;transition:all .2s;color:var(--muted);letter-spacing:.04em;margin-bottom:-1px;font-family:'Segoe UI',sans-serif}
.tab:hover{color:var(--text);background:var(--card)}
.tab.active{color:var(--text);background:var(--card);border-color:var(--border);border-bottom-color:var(--card)}
.tab.t-all{color:var(--accent)}
.tab.t-ssh.active{border-top:2px solid var(--ssh);color:var(--ssh)}
.tab.t-vmess.active{border-top:2px solid var(--vmess);color:var(--vmess)}
.tab.t-vless.active{border-top:2px solid var(--vless);color:var(--vless)}
.tab.t-trojan.active{border-top:2px solid var(--trojan);color:var(--trojan)}
.tab.t-del.active{border-top:2px solid var(--del);color:var(--del)}
.tab-content{display:none}
.tab-content.active{display:block}

/* Section heading */
.sh{display:flex;align-items:center;gap:10px;margin:28px 0 14px;padding-left:0}
.sh-line{flex:1;height:1px;background:linear-gradient(90deg,var(--border2),transparent)}
.sh-label{font-size:.7rem;font-weight:700;letter-spacing:.12em;color:var(--muted);font-family:'Segoe UI',sans-serif}
.sh-dot{width:6px;height:6px;border-radius:50%}

/* Endpoint cards */
.ep{background:var(--card);border:1px solid var(--border);border-radius:12px;margin-bottom:10px;overflow:hidden;transition:border-color .2s}
.ep:hover{border-color:var(--border2)}
.ep-hd{display:flex;align-items:center;gap:10px;padding:14px 16px;cursor:pointer;transition:background .15s}
.ep-hd:hover{background:rgba(255,255,255,.02)}
.mth{padding:4px 10px;border-radius:5px;font-size:.68rem;font-weight:800;min-width:44px;text-align:center;letter-spacing:.05em}
.get{background:rgba(16,185,129,.15);color:var(--ssh);border:1px solid rgba(16,185,129,.3)}
.del-mth{background:rgba(239,68,68,.15);color:var(--del);border:1px solid rgba(239,68,68,.3)}
.pth{font-size:.85rem;flex:1;color:var(--text)}
.pth .pm{color:var(--accent4);font-size:.78rem}
.dsc{font-size:.73rem;color:var(--muted);font-family:'Segoe UI',sans-serif}
.tags{display:flex;gap:5px;align-items:center}
.tag{font-size:.62rem;padding:2px 8px;border-radius:10px;font-weight:700;letter-spacing:.04em}
.t-ssh{background:rgba(16,185,129,.15);color:var(--ssh);border:1px solid rgba(16,185,129,.25)}
.t-vmess{background:rgba(59,130,246,.15);color:var(--vmess);border:1px solid rgba(59,130,246,.25)}
.t-vless{background:rgba(139,92,246,.15);color:var(--vless);border:1px solid rgba(139,92,246,.25)}
.t-trojan{background:rgba(244,63,94,.15);color:var(--trojan);border:1px solid rgba(244,63,94,.25)}
.t-trial{background:rgba(245,158,11,.15);color:var(--trial);border:1px solid rgba(245,158,11,.25)}
.t-del{background:rgba(239,68,68,.15);color:var(--del);border:1px solid rgba(239,68,68,.25)}
.chevron{color:var(--muted);font-size:.7rem;transition:transform .2s}
.ep-bd{display:none;border-top:1px solid var(--border);padding:18px}
.ep-bd.open{display:block}
.ep-bd.open + .ep-hd .chevron,.ep-hd.open .chevron{transform:rotate(180deg)}

/* Param table */
.ptbl{width:100%;border-collapse:collapse;font-size:.78rem;margin-bottom:14px;font-family:'Segoe UI',sans-serif}
.ptbl th{background:rgba(255,255,255,.03);color:var(--muted);text-align:left;padding:7px 12px;font-weight:600;border-bottom:1px solid var(--border)}
.ptbl td{padding:7px 12px;border-bottom:1px solid rgba(255,255,255,.03);vertical-align:top}
.ptbl td:first-child{color:var(--accent);font-family:'SF Mono','Fira Code',monospace;font-size:.8rem}
.req{background:rgba(239,68,68,.15);color:var(--del);border:1px solid rgba(239,68,68,.25);padding:2px 7px;border-radius:4px;font-size:.65rem;font-weight:700}
.opt{background:rgba(16,185,129,.1);color:var(--ssh);border:1px solid rgba(16,185,129,.2);padding:2px 7px;border-radius:4px;font-size:.65rem;font-weight:700}

/* URL box */
.url-label{font-size:.68rem;color:var(--muted);letter-spacing:.06em;margin-bottom:6px;font-family:'Segoe UI',sans-serif}
.url-box{background:#080d18;border:1px solid var(--border2);border-radius:8px;padding:10px 14px;font-size:.75rem;color:var(--accent);word-break:break-all;margin-bottom:12px;position:relative;padding-right:80px;line-height:1.5}
.cp{position:absolute;right:10px;top:50%;transform:translateY(-50%);background:rgba(0,212,255,.12);border:1px solid rgba(0,212,255,.25);color:var(--accent);padding:4px 10px;border-radius:5px;cursor:pointer;font-size:.68rem;font-weight:700;white-space:nowrap;transition:all .2s;font-family:'Segoe UI',sans-serif}
.cp:hover{background:rgba(0,212,255,.25)}
.cp.ok{background:rgba(16,185,129,.15);border-color:rgba(16,185,129,.3);color:var(--ssh)}

/* Response box */
.rb-label{font-size:.68rem;color:var(--muted);letter-spacing:.06em;margin-bottom:6px;font-family:'Segoe UI',sans-serif}
.rb{background:#060a14;border:1px solid var(--border);border-radius:8px;padding:14px;font-size:.76rem;line-height:1.7;max-height:280px;overflow-y:auto;color:#94a3b8}
.rb .k{color:#79c0ff}
.rb .s{color:#a5d6a7}
.rb .n{color:#ffb74d}
.rb .b{color:#ef9a9a}

/* Try it */
.try-section{background:rgba(0,212,255,.04);border:1px solid rgba(0,212,255,.12);border-radius:10px;padding:16px;margin-top:14px}
.try-title{font-size:.72rem;color:var(--accent);letter-spacing:.08em;margin-bottom:12px;font-family:'Segoe UI',sans-serif;font-weight:700}
.try-inputs{display:flex;flex-wrap:wrap;gap:8px;margin-bottom:10px}
.try-input{background:#080d18;border:1px solid var(--border2);border-radius:6px;padding:7px 10px;color:var(--text);font-size:.78rem;flex:1;min-width:100px;outline:none;font-family:inherit}
.try-input:focus{border-color:var(--accent);box-shadow:0 0 0 2px rgba(0,212,255,.1)}
.try-input::placeholder{color:var(--muted)}
.try-run{background:linear-gradient(135deg,var(--accent),var(--accent2));border:none;border-radius:6px;padding:7px 18px;color:#fff;font-size:.78rem;font-weight:700;cursor:pointer;font-family:'Segoe UI',sans-serif;white-space:nowrap}
.try-run:hover{opacity:.9}
.try-out{background:#060a14;border:1px solid var(--border);border-radius:6px;padding:12px;font-size:.74rem;color:#94a3b8;max-height:200px;overflow-y:auto;margin-top:8px;display:none;white-space:pre-wrap;word-break:break-all}

/* Footer */
.ftr{text-align:center;padding:40px 0 20px;color:var(--muted);font-size:.75rem;font-family:'Segoe UI',sans-serif}
.ftr a{color:var(--accent);text-decoration:none}

/* Scrollbar */
::-webkit-scrollbar{width:5px;height:5px}
::-webkit-scrollbar-track{background:var(--bg)}
::-webkit-scrollbar-thumb{background:var(--border2);border-radius:10px}

@media(max-width:600px){.hero h1{font-size:1.7rem}.hdr-right{display:none}.tabs{gap:4px}.tab{padding:7px 12px;font-size:.72rem}}
</style>
</head>
<body>

<!-- Header -->
<div class="hdr">
  <div class="hdr-inner">
    <div class="logo">
      <div class="logo-icon">⚡</div>
      <div class="logo-text">NEXUS<span>DEV</span> <span style="color:var(--muted);font-weight:400;font-size:.8rem">API</span></div>
    </div>
    <div class="hdr-right">
      <span class="badge badge-live">● LIVE</span>
      <span class="badge badge-ver">v4.0</span>
      <div class="key-pill">🔑 <span>${auth || 'not set'}</span></div>
    </div>
  </div>
</div>

<div class="wrap">

<!-- Hero -->
<div class="hero">
  <div class="hero-tag">⚡ REST API · HTTPS · No Port</div>
  <h1><span class="gr">NEXUSDEV</span><br>VPN Manager API</h1>
  <p style="font-family:'Segoe UI',sans-serif">Kelola akun SSH, VMess, VLess, Trojan via REST API. Semua endpoint HTTPS tanpa nomor port.</p>
  <div class="base-url">
    <span class="label">Base URL</span>
    <span class="val">${baseUrl}</span>
  </div>
</div>

<!-- Stats -->
<div class="stats">
  <div class="stat s1"><div class="stat-num">2</div><div class="stat-lbl">SSH ENDPOINTS</div></div>
  <div class="stat s2"><div class="stat-num">2</div><div class="stat-lbl">VMESS ENDPOINTS</div></div>
  <div class="stat s3"><div class="stat-num">2</div><div class="stat-lbl">VLESS ENDPOINTS</div></div>
  <div class="stat s4"><div class="stat-num">2</div><div class="stat-lbl">TROJAN ENDPOINTS</div></div>
  <div class="stat s5"><div class="stat-num">8</div><div class="stat-lbl">DELETE ENDPOINTS</div></div>
</div>

<!-- Tabs -->
<div class="tabs">
  <div class="tab t-all active" onclick="showTab('all',this)">🔷 Semua</div>
  <div class="tab t-ssh" onclick="showTab('ssh',this)">SSH</div>
  <div class="tab t-vmess" onclick="showTab('vmess',this)">VMess</div>
  <div class="tab t-vless" onclick="showTab('vless',this)">VLess</div>
  <div class="tab t-trojan" onclick="showTab('trojan',this)">Trojan</div>
  <div class="tab t-del" onclick="showTab('del',this)">🗑 Delete</div>
</div>

<!-- ═══ SSH ═══════════════════════════════════════════════════════════════════ -->
<div class="tab-content active" id="tab-all">
<div id="grp-ssh">
<div class="sh"><div class="sh-dot" style="background:var(--ssh)"></div><span class="sh-label">SSH / OPENVPN</span><div class="sh-line"></div></div>

<div class="ep">
  <div class="ep-hd" onclick="tog(this)">
    <span class="mth get">GET</span>
    <span class="pth">/api/trial-ssh</span>
    <span class="dsc">Trial SSH 60 menit</span>
    <div class="tags"><span class="tag t-ssh">SSH</span><span class="tag t-trial">TRIAL</span></div>
    <span class="chevron">▼</span>
  </div>
  <div class="ep-bd">
    <table class="ptbl"><tr><th>Parameter</th><th>Status</th><th>Keterangan</th></tr>
    <tr><td>auth</td><td><span class="req">WAJIB</span></td><td>API auth key</td></tr></table>
    <div class="url-label">ENDPOINT URL</div>
    <div class="url-box"><button class="cp" onclick="cpUrl(this)">Copy</button>${baseUrl}/api/trial-ssh?auth=${auth}</div>
    <div class="rb-label">RESPONSE</div>
    <div class="rb"><span class="k">"status"</span>: <span class="s">"success"</span>,<br><span class="k">"data"</span>: {<br>&nbsp;&nbsp;<span class="k">"username"</span>: <span class="s">"Trial64897"</span>,<br>&nbsp;&nbsp;<span class="k">"password"</span>: <span class="s">"1"</span>,<br>&nbsp;&nbsp;<span class="k">"host"</span>: <span class="s">"${domain}"</span>,<br>&nbsp;&nbsp;<span class="k">"ports"</span>: { <span class="k">"openSSH"</span>: <span class="s">"22"</span>, <span class="k">"dropbear"</span>: <span class="s">"143, 109"</span>, ... },<br>&nbsp;&nbsp;<span class="k">"expired"</span>: <span class="s">"60 Minutes"</span><br>}</div>
    <div class="try-section">
      <div class="try-title">⚡ TRY IT</div>
      <div style="display:flex;gap:8px;flex-wrap:wrap">
        <button class="try-run" onclick="tryApi('${baseUrl}/api/trial-ssh?auth=${auth}',this)">Run →</button>
      </div>
      <div class="try-out" id="out-trial-ssh"></div>
    </div>
  </div>
</div>

<div class="ep">
  <div class="ep-hd" onclick="tog(this)">
    <span class="mth get">GET</span>
    <span class="pth">/api/create-ssh <span class="pm">?user= &password= &exp= &limitip=</span></span>
    <span class="dsc">Buat akun SSH</span>
    <div class="tags"><span class="tag t-ssh">SSH</span></div>
    <span class="chevron">▼</span>
  </div>
  <div class="ep-bd">
    <table class="ptbl"><tr><th>Parameter</th><th>Status</th><th>Keterangan</th></tr>
    <tr><td>auth</td><td><span class="req">WAJIB</span></td><td>API auth key</td></tr>
    <tr><td>user</td><td><span class="req">WAJIB</span></td><td>Username akun</td></tr>
    <tr><td>password</td><td><span class="req">WAJIB</span></td><td>Password akun</td></tr>
    <tr><td>exp</td><td><span class="req">WAJIB</span></td><td>Masa aktif (hari)</td></tr>
    <tr><td>limitip</td><td><span class="opt">OPSIONAL</span></td><td>Maks IP login (default: 1)</td></tr></table>
    <div class="url-label">ENDPOINT URL</div>
    <div class="url-box"><button class="cp" onclick="cpUrl(this)">Copy</button>${baseUrl}/api/create-ssh?auth=${auth}&amp;user=myuser&amp;password=mypass&amp;exp=30&amp;limitip=2</div>
    <div class="rb-label">RESPONSE</div>
    <div class="rb"><span class="k">"status"</span>: <span class="s">"success"</span>,<br><span class="k">"data"</span>: {<br>&nbsp;&nbsp;<span class="k">"username"</span>: <span class="s">"myuser"</span>, <span class="k">"password"</span>: <span class="s">"mypass"</span>,<br>&nbsp;&nbsp;<span class="k">"host"</span>: <span class="s">"${domain}"</span>,<br>&nbsp;&nbsp;<span class="k">"ports"</span>: { ... },<br>&nbsp;&nbsp;<span class="k">"expired"</span>: <span class="s">"30 Days"</span>, <span class="k">"expiredDate"</span>: <span class="s">"04 Apr, 2026"</span>,<br>&nbsp;&nbsp;<span class="k">"saveLink"</span>: <span class="s">"https://${domain}:81/ssh-myuser.txt"</span><br>}</div>
    <div class="try-section">
      <div class="try-title">⚡ TRY IT</div>
      <div class="try-inputs">
        <input class="try-input" id="cs-user" placeholder="username">
        <input class="try-input" id="cs-pass" placeholder="password">
        <input class="try-input" id="cs-exp" placeholder="exp (hari)" style="max-width:100px">
        <input class="try-input" id="cs-lip" placeholder="limitip" style="max-width:80px">
        <button class="try-run" onclick="tryApi(\`${baseUrl}/api/create-ssh?auth=${auth}&user=\${gi('cs-user')}&password=\${gi('cs-pass')}&exp=\${gi('cs-exp')||30}&limitip=\${gi('cs-lip')||1}\`,this,'out-create-ssh')">Run →</button>
      </div>
      <div class="try-out" id="out-create-ssh"></div>
    </div>
  </div>
</div>

<!-- ─── VMess ─────────────────────────────────────────────────────────────── -->
<div id="grp-vmess">
<div class="sh"><div class="sh-dot" style="background:var(--vmess)"></div><span class="sh-label">VMESS (XRAY)</span><div class="sh-line"></div></div>

<div class="ep">
  <div class="ep-hd" onclick="tog(this)">
    <span class="mth get">GET</span>
    <span class="pth">/api/trial-vmess</span>
    <span class="dsc">Trial VMess 60 menit</span>
    <div class="tags"><span class="tag t-vmess">VMESS</span><span class="tag t-trial">TRIAL</span></div>
    <span class="chevron">▼</span>
  </div>
  <div class="ep-bd">
    <table class="ptbl"><tr><th>Parameter</th><th>Status</th><th>Keterangan</th></tr>
    <tr><td>auth</td><td><span class="req">WAJIB</span></td><td>API auth key</td></tr></table>
    <div class="url-label">ENDPOINT URL</div>
    <div class="url-box"><button class="cp" onclick="cpUrl(this)">Copy</button>${baseUrl}/api/trial-vmess?auth=${auth}</div>
    <div class="rb-label">RESPONSE</div>
    <div class="rb"><span class="k">"user"</span>: <span class="s">"Trial1234"</span>, <span class="k">"uuid"</span>: <span class="s">"xxxx-xxxx"</span>,<br><span class="k">"ws_tls"</span>: <span class="s">"vmess://eyJ2Ijoi..."</span>,<br><span class="k">"ws_none_tls"</span>: <span class="s">"vmess://eyJ2Ijoi..."</span>,<br><span class="k">"grpc"</span>: <span class="s">"vmess://eyJ2Ijoi..."</span>,<br><span class="k">"expired"</span>: <span class="s">"60 minutes"</span></div>
    <div class="try-section">
      <div class="try-title">⚡ TRY IT</div>
      <button class="try-run" onclick="tryApi('${baseUrl}/api/trial-vmess?auth=${auth}',this,'out-trial-vmess')">Run →</button>
      <div class="try-out" id="out-trial-vmess"></div>
    </div>
  </div>
</div>

<div class="ep">
  <div class="ep-hd" onclick="tog(this)">
    <span class="mth get">GET</span>
    <span class="pth">/api/create-vmess <span class="pm">?user= &quota= &limitip= &exp=</span></span>
    <span class="dsc">Buat akun VMess</span>
    <div class="tags"><span class="tag t-vmess">VMESS</span></div>
    <span class="chevron">▼</span>
  </div>
  <div class="ep-bd">
    <table class="ptbl"><tr><th>Parameter</th><th>Status</th><th>Keterangan</th></tr>
    <tr><td>auth</td><td><span class="req">WAJIB</span></td><td>API auth key</td></tr>
    <tr><td>user</td><td><span class="req">WAJIB</span></td><td>Username</td></tr>
    <tr><td>exp</td><td><span class="req">WAJIB</span></td><td>Masa aktif (hari)</td></tr>
    <tr><td>quota</td><td><span class="opt">OPSIONAL</span></td><td>Kuota GB (0=unlimited)</td></tr>
    <tr><td>limitip</td><td><span class="opt">OPSIONAL</span></td><td>Maks IP (default: 1)</td></tr></table>
    <div class="url-label">ENDPOINT URL</div>
    <div class="url-box"><button class="cp" onclick="cpUrl(this)">Copy</button>${baseUrl}/api/create-vmess?auth=${auth}&amp;user=myuser&amp;quota=10&amp;limitip=1&amp;exp=30</div>
    <div class="rb-label">RESPONSE</div>
    <div class="rb"><span class="k">"user"</span>: <span class="s">"myuser"</span>, <span class="k">"uuid"</span>: <span class="s">"xxxx-xxxx"</span>,<br><span class="k">"quota"</span>: <span class="s">"10 GB"</span>, <span class="k">"expired"</span>: <span class="s">"30 Days"</span>,<br><span class="k">"ws_tls"</span>: <span class="s">"vmess://..."</span>, <span class="k">"grpc"</span>: <span class="s">"vmess://..."</span></div>
    <div class="try-section">
      <div class="try-title">⚡ TRY IT</div>
      <div class="try-inputs">
        <input class="try-input" id="cv-user" placeholder="username">
        <input class="try-input" id="cv-exp" placeholder="exp (hari)" style="max-width:100px">
        <input class="try-input" id="cv-quota" placeholder="quota GB" style="max-width:90px">
        <button class="try-run" onclick="tryApi(\`${baseUrl}/api/create-vmess?auth=${auth}&user=\${gi('cv-user')}&exp=\${gi('cv-exp')||30}&quota=\${gi('cv-quota')||0}\`,this,'out-create-vmess')">Run →</button>
      </div>
      <div class="try-out" id="out-create-vmess"></div>
    </div>
  </div>
</div>

<!-- ─── VLess ─────────────────────────────────────────────────────────────── -->
<div id="grp-vless">
<div class="sh"><div class="sh-dot" style="background:var(--vless)"></div><span class="sh-label">VLESS (XRAY)</span><div class="sh-line"></div></div>

<div class="ep">
  <div class="ep-hd" onclick="tog(this)">
    <span class="mth get">GET</span>
    <span class="pth">/api/trial-vless</span>
    <span class="dsc">Trial VLess 60 menit</span>
    <div class="tags"><span class="tag t-vless">VLESS</span><span class="tag t-trial">TRIAL</span></div>
    <span class="chevron">▼</span>
  </div>
  <div class="ep-bd">
    <table class="ptbl"><tr><th>Parameter</th><th>Status</th><th>Keterangan</th></tr>
    <tr><td>auth</td><td><span class="req">WAJIB</span></td><td>API auth key</td></tr></table>
    <div class="url-label">ENDPOINT URL</div>
    <div class="url-box"><button class="cp" onclick="cpUrl(this)">Copy</button>${baseUrl}/api/trial-vless?auth=${auth}</div>
    <div class="rb-label">RESPONSE</div>
    <div class="rb"><span class="k">"user"</span>: <span class="s">"Trial6813"</span>, <span class="k">"uuid"</span>: <span class="s">"xxxx-xxxx"</span>,<br><span class="k">"ws_tls"</span>: <span class="s">"vless://uuid@${domain}:443?..."</span>,<br><span class="k">"grpc"</span>: <span class="s">"vless://uuid@${domain}:443?mode=gun..."</span>,<br><span class="k">"expired"</span>: <span class="s">"60 minutes"</span></div>
    <div class="try-section">
      <div class="try-title">⚡ TRY IT</div>
      <button class="try-run" onclick="tryApi('${baseUrl}/api/trial-vless?auth=${auth}',this,'out-trial-vless')">Run →</button>
      <div class="try-out" id="out-trial-vless"></div>
    </div>
  </div>
</div>

<div class="ep">
  <div class="ep-hd" onclick="tog(this)">
    <span class="mth get">GET</span>
    <span class="pth">/api/create-vless <span class="pm">?user= &quota= &limitip= &exp=</span></span>
    <span class="dsc">Buat akun VLess</span>
    <div class="tags"><span class="tag t-vless">VLESS</span></div>
    <span class="chevron">▼</span>
  </div>
  <div class="ep-bd">
    <table class="ptbl"><tr><th>Parameter</th><th>Status</th><th>Keterangan</th></tr>
    <tr><td>auth</td><td><span class="req">WAJIB</span></td><td>API auth key</td></tr>
    <tr><td>user</td><td><span class="req">WAJIB</span></td><td>Username</td></tr>
    <tr><td>exp</td><td><span class="req">WAJIB</span></td><td>Masa aktif (hari)</td></tr>
    <tr><td>quota</td><td><span class="opt">OPSIONAL</span></td><td>Kuota GB</td></tr>
    <tr><td>limitip</td><td><span class="opt">OPSIONAL</span></td><td>Maks IP</td></tr></table>
    <div class="url-label">ENDPOINT URL</div>
    <div class="url-box"><button class="cp" onclick="cpUrl(this)">Copy</button>${baseUrl}/api/create-vless?auth=${auth}&amp;user=myuser&amp;quota=10&amp;limitip=1&amp;exp=30</div>
    <div class="rb-label">RESPONSE</div>
    <div class="rb"><span class="k">"user"</span>: <span class="s">"myuser"</span>, <span class="k">"uuid"</span>: <span class="s">"xxxx-xxxx"</span>,<br><span class="k">"ws_tls"</span>: <span class="s">"vless://..."</span>, <span class="k">"grpc"</span>: <span class="s">"vless://..."</span>,<br><span class="k">"expired"</span>: <span class="s">"30 Days"</span>, <span class="k">"quota"</span>: <span class="s">"10 GB"</span></div>
    <div class="try-section">
      <div class="try-title">⚡ TRY IT</div>
      <div class="try-inputs">
        <input class="try-input" id="cvl-user" placeholder="username">
        <input class="try-input" id="cvl-exp" placeholder="exp (hari)" style="max-width:100px">
        <input class="try-input" id="cvl-quota" placeholder="quota GB" style="max-width:90px">
        <button class="try-run" onclick="tryApi(\`${baseUrl}/api/create-vless?auth=${auth}&user=\${gi('cvl-user')}&exp=\${gi('cvl-exp')||30}&quota=\${gi('cvl-quota')||0}\`,this,'out-create-vless')">Run →</button>
      </div>
      <div class="try-out" id="out-create-vless"></div>
    </div>
  </div>
</div>

<!-- ─── Trojan ────────────────────────────────────────────────────────────── -->
<div id="grp-trojan">
<div class="sh"><div class="sh-dot" style="background:var(--trojan)"></div><span class="sh-label">TROJAN (XRAY)</span><div class="sh-line"></div></div>

<div class="ep">
  <div class="ep-hd" onclick="tog(this)">
    <span class="mth get">GET</span>
    <span class="pth">/api/trial-trojan</span>
    <span class="dsc">Trial Trojan 60 menit</span>
    <div class="tags"><span class="tag t-trojan">TROJAN</span><span class="tag t-trial">TRIAL</span></div>
    <span class="chevron">▼</span>
  </div>
  <div class="ep-bd">
    <table class="ptbl"><tr><th>Parameter</th><th>Status</th><th>Keterangan</th></tr>
    <tr><td>auth</td><td><span class="req">WAJIB</span></td><td>API auth key</td></tr></table>
    <div class="url-label">ENDPOINT URL</div>
    <div class="url-box"><button class="cp" onclick="cpUrl(this)">Copy</button>${baseUrl}/api/trial-trojan?auth=${auth}</div>
    <div class="rb-label">RESPONSE</div>
    <div class="rb"><span class="k">"user"</span>: <span class="s">"Trial7804"</span>, <span class="k">"uuid"</span>: <span class="s">"xxxx-xxxx"</span>,<br><span class="k">"ws"</span>: <span class="s">"trojan://uuid@${domain}:443?..."</span>,<br><span class="k">"grpc"</span>: <span class="s">"trojan://uuid@${domain}:443?mode=gun..."</span>,<br><span class="k">"expired"</span>: <span class="s">"60 minutes"</span></div>
    <div class="try-section">
      <div class="try-title">⚡ TRY IT</div>
      <button class="try-run" onclick="tryApi('${baseUrl}/api/trial-trojan?auth=${auth}',this,'out-trial-trojan')">Run →</button>
      <div class="try-out" id="out-trial-trojan"></div>
    </div>
  </div>
</div>

<div class="ep">
  <div class="ep-hd" onclick="tog(this)">
    <span class="mth get">GET</span>
    <span class="pth">/api/create-trojan <span class="pm">?user= &quota= &limitip= &exp=</span></span>
    <span class="dsc">Buat akun Trojan</span>
    <div class="tags"><span class="tag t-trojan">TROJAN</span></div>
    <span class="chevron">▼</span>
  </div>
  <div class="ep-bd">
    <table class="ptbl"><tr><th>Parameter</th><th>Status</th><th>Keterangan</th></tr>
    <tr><td>auth</td><td><span class="req">WAJIB</span></td><td>API auth key</td></tr>
    <tr><td>user</td><td><span class="req">WAJIB</span></td><td>Username</td></tr>
    <tr><td>exp</td><td><span class="req">WAJIB</span></td><td>Masa aktif (hari)</td></tr>
    <tr><td>quota</td><td><span class="opt">OPSIONAL</span></td><td>Kuota GB</td></tr>
    <tr><td>limitip</td><td><span class="opt">OPSIONAL</span></td><td>Maks IP</td></tr></table>
    <div class="url-label">ENDPOINT URL</div>
    <div class="url-box"><button class="cp" onclick="cpUrl(this)">Copy</button>${baseUrl}/api/create-trojan?auth=${auth}&amp;user=myuser&amp;quota=10&amp;limitip=1&amp;exp=30</div>
    <div class="rb-label">RESPONSE</div>
    <div class="rb"><span class="k">"user"</span>: <span class="s">"myuser"</span>, <span class="k">"uuid"</span>: <span class="s">"xxxx-xxxx"</span>,<br><span class="k">"ws"</span>: <span class="s">"trojan://..."</span>, <span class="k">"grpc"</span>: <span class="s">"trojan://..."</span>,<br><span class="k">"expired"</span>: <span class="s">"30 Days"</span>, <span class="k">"quota"</span>: <span class="s">"10 GB"</span></div>
    <div class="try-section">
      <div class="try-title">⚡ TRY IT</div>
      <div class="try-inputs">
        <input class="try-input" id="ct-user" placeholder="username">
        <input class="try-input" id="ct-exp" placeholder="exp (hari)" style="max-width:100px">
        <input class="try-input" id="ct-quota" placeholder="quota GB" style="max-width:90px">
        <button class="try-run" onclick="tryApi(\`${baseUrl}/api/create-trojan?auth=${auth}&user=\${gi('ct-user')}&exp=\${gi('ct-exp')||30}&quota=\${gi('ct-quota')||0}\`,this,'out-create-trojan')">Run →</button>
      </div>
      <div class="try-out" id="out-create-trojan"></div>
    </div>
  </div>
</div>

<!-- ─── DELETE ────────────────────────────────────────────────────────────── -->
<div id="grp-del">
<div class="sh"><div class="sh-dot" style="background:var(--del)"></div><span class="sh-label">DELETE ACCOUNTS</span><div class="sh-line"></div></div>

<!-- ── SSH Delete ── -->
<div class="ep">
  <div class="ep-hd" onclick="tog(this)">
    <span class="mth del-mth">GET</span>
    <span class="pth">/api/delssh &nbsp;<span class="pm" style="color:var(--muted);font-size:.72rem">alias: /api/delete-ssh</span> <span class="pm">?username=</span></span>
    <span class="dsc">Hapus akun SSH</span>
    <div class="tags"><span class="tag t-del">DELETE</span><span class="tag t-ssh">SSH</span></div>
    <span class="chevron">▼</span>
  </div>
  <div class="ep-bd">
    <table class="ptbl"><tr><th>Parameter</th><th>Status</th><th>Keterangan</th></tr>
    <tr><td>auth</td><td><span class="req">WAJIB</span></td><td>API auth key</td></tr>
    <tr><td>username</td><td><span class="req">WAJIB</span></td><td>Username akun SSH yang dihapus</td></tr></table>
    <div class="url-label">ENDPOINT URL (SHORT)</div>
    <div class="url-box"><button class="cp" onclick="cpUrl(this)">Copy</button>${baseUrl}/api/delssh?auth=${auth}&amp;username=myuser</div>
    <div class="url-label">ENDPOINT URL (LONG)</div>
    <div class="url-box"><button class="cp" onclick="cpUrl(this)">Copy</button>${baseUrl}/api/delete-ssh?auth=${auth}&amp;username=myuser</div>
    <div class="rb-label">RESPONSE</div>
    <div class="rb"><span class="k">"status"</span>: <span class="s">"success"</span>,<br><span class="k">"message"</span>: <span class="s">"SSH account myuser deleted successfully"</span></div>
    <div class="try-section">
      <div class="try-title">⚡ TRY IT</div>
      <div class="try-inputs">
        <input class="try-input" id="ds-user" placeholder="username">
        <button class="try-run" style="background:linear-gradient(135deg,#ef4444,#b91c1c)" onclick="tryApi(\`${baseUrl}/api/delssh?auth=${auth}&username=\${gi('ds-user')}\`,this,'out-del-ssh')">Delete →</button>
      </div>
      <div class="try-out" id="out-del-ssh"></div>
    </div>
  </div>
</div>

<!-- ── VMess Delete ── -->
<div class="ep">
  <div class="ep-hd" onclick="tog(this)">
    <span class="mth del-mth">GET</span>
    <span class="pth">/api/delws &nbsp;<span class="pm" style="color:var(--muted);font-size:.72rem">alias: /api/delete-vmess</span> <span class="pm">?username=</span></span>
    <span class="dsc">Hapus akun VMess</span>
    <div class="tags"><span class="tag t-del">DELETE</span><span class="tag t-vmess">VMESS</span></div>
    <span class="chevron">▼</span>
  </div>
  <div class="ep-bd">
    <table class="ptbl"><tr><th>Parameter</th><th>Status</th><th>Keterangan</th></tr>
    <tr><td>auth</td><td><span class="req">WAJIB</span></td><td>API auth key</td></tr>
    <tr><td>username</td><td><span class="req">WAJIB</span></td><td>Username akun VMess yang dihapus</td></tr></table>
    <div class="url-label">ENDPOINT URL (SHORT)</div>
    <div class="url-box"><button class="cp" onclick="cpUrl(this)">Copy</button>${baseUrl}/api/delws?auth=${auth}&amp;username=myuser</div>
    <div class="url-label">ENDPOINT URL (LONG)</div>
    <div class="url-box"><button class="cp" onclick="cpUrl(this)">Copy</button>${baseUrl}/api/delete-vmess?auth=${auth}&amp;username=myuser</div>
    <div class="rb-label">RESPONSE</div>
    <div class="rb"><span class="k">"status"</span>: <span class="s">"success"</span>,<br><span class="k">"message"</span>: <span class="s">"VMess account myuser deleted successfully"</span></div>
    <div class="try-section">
      <div class="try-title">⚡ TRY IT</div>
      <div class="try-inputs">
        <input class="try-input" id="dv-user" placeholder="username">
        <button class="try-run" style="background:linear-gradient(135deg,#ef4444,#b91c1c)" onclick="tryApi(\`${baseUrl}/api/delws?auth=${auth}&username=\${gi('dv-user')}\`,this,'out-del-vmess')">Delete →</button>
      </div>
      <div class="try-out" id="out-del-vmess"></div>
    </div>
  </div>
</div>

<!-- ── VLess Delete ── -->
<div class="ep">
  <div class="ep-hd" onclick="tog(this)">
    <span class="mth del-mth">GET</span>
    <span class="pth">/api/delvl &nbsp;<span class="pm" style="color:var(--muted);font-size:.72rem">alias: /api/delete-vless</span> <span class="pm">?username=</span></span>
    <span class="dsc">Hapus akun VLess</span>
    <div class="tags"><span class="tag t-del">DELETE</span><span class="tag t-vless">VLESS</span></div>
    <span class="chevron">▼</span>
  </div>
  <div class="ep-bd">
    <table class="ptbl"><tr><th>Parameter</th><th>Status</th><th>Keterangan</th></tr>
    <tr><td>auth</td><td><span class="req">WAJIB</span></td><td>API auth key</td></tr>
    <tr><td>username</td><td><span class="req">WAJIB</span></td><td>Username akun VLess yang dihapus</td></tr></table>
    <div class="url-label">ENDPOINT URL (SHORT)</div>
    <div class="url-box"><button class="cp" onclick="cpUrl(this)">Copy</button>${baseUrl}/api/delvl?auth=${auth}&amp;username=myuser</div>
    <div class="url-label">ENDPOINT URL (LONG)</div>
    <div class="url-box"><button class="cp" onclick="cpUrl(this)">Copy</button>${baseUrl}/api/delete-vless?auth=${auth}&amp;username=myuser</div>
    <div class="rb-label">RESPONSE</div>
    <div class="rb"><span class="k">"status"</span>: <span class="s">"success"</span>,<br><span class="k">"message"</span>: <span class="s">"VLess account myuser deleted successfully"</span></div>
    <div class="try-section">
      <div class="try-title">⚡ TRY IT</div>
      <div class="try-inputs">
        <input class="try-input" id="dvl-user" placeholder="username">
        <button class="try-run" style="background:linear-gradient(135deg,#ef4444,#b91c1c)" onclick="tryApi(\`${baseUrl}/api/delvl?auth=${auth}&username=\${gi('dvl-user')}\`,this,'out-del-vless')">Delete →</button>
      </div>
      <div class="try-out" id="out-del-vless"></div>
    </div>
  </div>
</div>

<!-- ── Trojan Delete ── -->
<div class="ep">
  <div class="ep-hd" onclick="tog(this)">
    <span class="mth del-mth">GET</span>
    <span class="pth">/api/deltr &nbsp;<span class="pm" style="color:var(--muted);font-size:.72rem">alias: /api/delete-trojan</span> <span class="pm">?username=</span></span>
    <span class="dsc">Hapus akun Trojan</span>
    <div class="tags"><span class="tag t-del">DELETE</span><span class="tag t-trojan">TROJAN</span></div>
    <span class="chevron">▼</span>
  </div>
  <div class="ep-bd">
    <table class="ptbl"><tr><th>Parameter</th><th>Status</th><th>Keterangan</th></tr>
    <tr><td>auth</td><td><span class="req">WAJIB</span></td><td>API auth key</td></tr>
    <tr><td>username</td><td><span class="req">WAJIB</span></td><td>Username akun Trojan yang dihapus</td></tr></table>
    <div class="url-label">ENDPOINT URL (SHORT)</div>
    <div class="url-box"><button class="cp" onclick="cpUrl(this)">Copy</button>${baseUrl}/api/deltr?auth=${auth}&amp;username=myuser</div>
    <div class="url-label">ENDPOINT URL (LONG)</div>
    <div class="url-box"><button class="cp" onclick="cpUrl(this)">Copy</button>${baseUrl}/api/delete-trojan?auth=${auth}&amp;username=myuser</div>
    <div class="rb-label">RESPONSE</div>
    <div class="rb"><span class="k">"status"</span>: <span class="s">"success"</span>,<br><span class="k">"message"</span>: <span class="s">"Trojan account myuser deleted successfully"</span></div>
    <div class="try-section">
      <div class="try-title">⚡ TRY IT</div>
      <div class="try-inputs">
        <input class="try-input" id="dt-user" placeholder="username">
        <button class="try-run" style="background:linear-gradient(135deg,#ef4444,#b91c1c)" onclick="tryApi(\`${baseUrl}/api/deltr?auth=${auth}&username=\${gi('dt-user')}\`,this,'out-del-trojan')">Delete →</button>
      </div>
      <div class="try-out" id="out-del-trojan"></div>
    </div>
  </div>
</div>
</div><!-- end grp-del -->
</div><!-- end grp-trojan -->
</div><!-- end grp-vless -->
</div><!-- end grp-vmess -->
</div><!-- end grp-ssh -->
</div><!-- end tab-all -->

<div class="ftr">⚡ NEXUSDEV API · HTTPS via Nginx · <a href="https://t.me/nexusdev">@nexusweb_dev</a></div>
</div>

<script>
function gi(id){return document.getElementById(id)?.value?.trim()||''}

function tog(hd){
  const bd=hd.nextElementSibling;
  const open=bd.classList.toggle('open');
  hd.querySelector('.chevron').style.transform=open?'rotate(180deg)':'rotate(0deg)';
}

function cpUrl(btn){
  const t=btn.parentElement.textContent.replace('Copy','').trim();
  navigator.clipboard.writeText(t).then(()=>{
    btn.textContent='✓ OK'; btn.classList.add('ok');
    setTimeout(()=>{btn.textContent='Copy';btn.classList.remove('ok')},1800);
  });
}

async function tryApi(url,btn,outId){
  const out=document.getElementById(outId);
  if(!out)return;
  const orig=btn.textContent;
  btn.textContent='...'; btn.disabled=true;
  out.style.display='block'; out.textContent='⏳ Loading...';
  try{
    const r=await fetch(url);
    const j=await r.json();
    out.textContent=JSON.stringify(j,null,2);
  }catch(e){
    out.textContent='❌ Error: '+e.message;
  }
  btn.textContent=orig; btn.disabled=false;
}

function showTab(name,el){
  document.querySelectorAll('.tabs .tab').forEach(t=>t.classList.remove('active'));
  el.classList.add('active');
  const all=document.getElementById('tab-all');
  all.classList.add('active');
  const grps=['ssh','vmess','vless','trojan','del'];
  if(name==='all'){
    grps.forEach(g=>{const el=document.getElementById('grp-'+g);if(el)el.style.display=''});
  } else {
    grps.forEach(g=>{const el=document.getElementById('grp-'+g);if(el)el.style.display=g===name?'':'none'});
  }
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

  // Delete routes (long form)
  if (pathname === '/api/delete-ssh')    return handleDeleteSSH(params, res);
  if (pathname === '/api/delete-vmess')  return handleDeleteVmess(params, res);
  if (pathname === '/api/delete-vless')  return handleDeleteVless(params, res);
  if (pathname === '/api/delete-trojan') return handleDeleteTrojan(params, res);

  // Delete routes (short alias — ?username= or ?user=)
  if (pathname === '/api/delssh')  return handleDeleteSSH(params, res);
  if (pathname === '/api/delws')   return handleDeleteVmess(params, res);
  if (pathname === '/api/delvl')   return handleDeleteVless(params, res);
  if (pathname === '/api/deltr')   return handleDeleteTrojan(params, res);

  sendJSON(res, 404, { status: 'error', message: `Not found: ${pathname} — see /api/doc.html` });
});

server.listen(PORT, HOST, () => {
  console.log(`[NEXUSDEV API] Listening on ${HOST}:${PORT}`);
  console.log(`[NEXUSDEV API] Proxied via Nginx → https://${getDomain()}/api/`);
});
