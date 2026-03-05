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

function handleDocPage(res) {
  const domain  = getDomain();
  const auth    = getAuth();
  const baseUrl = `https://${domain}`;

  const html = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1.0">
<title>NEXUSDEV — API Docs</title>
<style>
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:'Segoe UI',sans-serif;background:#0d1117;color:#e6edf3;min-height:100vh}
.hdr{background:linear-gradient(135deg,#161b22,#21262d);border-bottom:1px solid #30363d;padding:22px 28px;display:flex;align-items:center;justify-content:space-between;flex-wrap:wrap;gap:12px}
.hdr h1{font-size:1.35rem;color:#58a6ff}
.hdr .sub{color:#8b949e;font-size:.82rem;margin-top:4px}
.badge{background:#238636;color:#fff;padding:3px 10px;border-radius:12px;font-size:.72rem;font-weight:700}
.wrap{max-width:1050px;margin:0 auto;padding:28px 14px}
.auth-card{background:#161b22;border:1px solid #f0883e55;border-radius:10px;padding:16px 20px;margin-bottom:28px;display:flex;flex-wrap:wrap;gap:10px;align-items:center}
.auth-card .lbl{color:#f0883e;font-size:.8rem;font-weight:700;white-space:nowrap}
.auth-card .val{font-family:monospace;font-size:.95rem;color:#ffa657;word-break:break-all}
.notice{background:#161b22;border:1px solid #30363d;border-radius:8px;padding:11px 16px;margin-bottom:22px;font-size:.83rem;color:#8b949e;line-height:1.6}
.notice code{color:#ffa657;background:#21262d;padding:1px 5px;border-radius:3px}
.sh{font-size:1rem;color:#79c0ff;font-weight:700;margin:28px 0 12px;border-left:3px solid #79c0ff;padding-left:10px;display:flex;align-items:center;gap:8px}
.ep{background:#161b22;border:1px solid #30363d;border-radius:10px;margin-bottom:11px;overflow:hidden}
.ep-hd{display:flex;align-items:center;gap:10px;padding:13px 16px;cursor:pointer;user-select:none}
.ep-hd:hover{background:#1c2128}
.mth{padding:3px 9px;border-radius:4px;font-size:.72rem;font-weight:800;min-width:46px;text-align:center}
.get{background:#1a7f37;color:#aff5b4}
.pth{font-family:monospace;font-size:.88rem;flex:1}
.dsc{font-size:.78rem;color:#8b949e}
.tag{font-size:.68rem;padding:2px 7px;border-radius:8px;font-weight:700}
.t-ssh{background:#1a7f37;color:#aff5b4}
.t-vm{background:#1461a8;color:#a5d6ff}
.t-vl{background:#6e40c9;color:#d2a8ff}
.t-tr{background:#9a1616;color:#ffa198}
.t-trial{background:#9e6a03;color:#ffa657}
.ep-bd{display:none;padding:16px;border-top:1px solid #21262d;background:#0d1117}
.ep-bd.open{display:block}
table{width:100%;border-collapse:collapse;font-size:.82rem;margin-bottom:14px}
th{background:#161b22;color:#8b949e;text-align:left;padding:7px 11px}
td{border-top:1px solid #21262d;padding:7px 11px}
.req{color:#f85149;font-size:.72rem;font-weight:700}
.opt{color:#3fb950;font-size:.72rem}
.url-box{background:#161b22;border:1px solid #30363d;border-radius:6px;padding:9px 13px;font-family:monospace;font-size:.78rem;color:#79c0ff;word-break:break-all;margin-bottom:11px;position:relative}
.cp{position:absolute;right:8px;top:50%;transform:translateY(-50%);background:#21262d;border:1px solid #30363d;color:#8b949e;padding:3px 9px;border-radius:4px;cursor:pointer;font-size:.72rem}
.cp:hover{background:#30363d;color:#e6edf3}
.rb{background:#161b22;border:1px solid #30363d;border-radius:6px;padding:13px;font-family:monospace;font-size:.78rem;white-space:pre-wrap;color:#aff5b4;max-height:320px;overflow-y:auto}
.ftr{text-align:center;color:#484f58;font-size:.78rem;margin-top:44px;padding-bottom:28px}
.ftr a{color:#58a6ff}
</style>
</head>
<body>
<div class="hdr">
  <div>
    <h1>⚡ NEXUSDEV — REST API</h1>
    <div class="sub">Base URL: <code style="color:#79c0ff;font-family:monospace">${baseUrl}</code> &nbsp;·&nbsp; All endpoints served via <strong>HTTPS port 443</strong></div>
  </div>
  <span class="badge">v4.0 LTS</span>
</div>
<div class="wrap">

<div class="auth-card">
  <span class="lbl">🔑 AUTH KEY:</span>
  <span class="val">${auth || '(not set — check /etc/ssh/api_auth.key)'}</span>
</div>

<div class="notice">
  Semua endpoint membutuhkan parameter <code>?auth=YOUR_KEY</code>.
  Akses melalui HTTPS tanpa nomor port: <code>${baseUrl}/api/trial-ssh?auth=${auth}</code>
</div>

<!-- ═══ SSH ═══ -->
<div class="sh"><span class="tag t-ssh">SSH</span> SSH / OpenVPN</div>

<div class="ep">
  <div class="ep-hd" onclick="tog(this)">
    <span class="mth get">GET</span>
    <span class="pth">/api/trial-ssh</span>
    <span class="dsc">Trial SSH 60 menit</span>
    <span class="tag t-trial">TRIAL</span>
  </div>
  <div class="ep-bd">
    <table><tr><th>Parameter</th><th>Status</th><th>Keterangan</th></tr>
    <tr><td>auth</td><td><span class="req">wajib</span></td><td>API auth key</td></tr></table>
    <div class="url-box"><button class="cp" onclick="cp(this)">Copy</button>${baseUrl}/api/trial-ssh?auth=${auth}</div>
    <div class="rb">{
  "status": "success",
  "data": {
    "username": "Trial64897",
    "password": "1",
    "host": "${domain}",
    "ip": "x.x.x.x",
    "ports": {
      "openSSH": "22",
      "dropbear": "143, 109",
      "dropbearWS": "443, 109",
      "sshUDP": "1-65535",
      "ovpnWSSSL": "443",
      "ovpnSSL": "443",
      "ovpnTCP": "1194",
      "ovpnUDP": "2200",
      "badVPN": "7100, 7300",
      "sshWS": "80, 8080",
      "sshWSSSL": "443"
    },
    "formats": {
      "port80":  "${domain}:80@Trial64897:1",
      "port443": "${domain}:443@Trial64897:1",
      "udp":     "${domain}:54-65535@Trial64897:1"
    },
    "ovpnDownload": "https://${domain}:81",
    "saveLink": "https://${domain}:81/ssh-Trial64897.txt",
    "payloads": {
      "wsNtls":   "GET / HTTP/1.1[crlf]Host: [host][crlf]...",
      "wsTls":    "GET wss://${domain}/ HTTP/1.1[crlf]...",
      "enhanced": "PATCH / HTTP/1.1[crlf]Host: ${domain}[crlf]..."
    },
    "created": "05 Mar, 2026",
    "expired": "60 Minutes",
    "isp": "CV. Rumahweb Indonesia",
    "city": "Jakarta"
  }
}</div>
  </div>
</div>

<div class="ep">
  <div class="ep-hd" onclick="tog(this)">
    <span class="mth get">GET</span>
    <span class="pth">/api/create-ssh</span>
    <span class="dsc">Buat akun SSH</span>
    <span class="tag t-ssh">SSH</span>
  </div>
  <div class="ep-bd">
    <table><tr><th>Parameter</th><th>Status</th><th>Keterangan</th></tr>
    <tr><td>auth</td><td><span class="req">wajib</span></td><td>API auth key</td></tr>
    <tr><td>user</td><td><span class="req">wajib</span></td><td>Username</td></tr>
    <tr><td>password</td><td><span class="req">wajib</span></td><td>Password</td></tr>
    <tr><td>exp</td><td><span class="req">wajib</span></td><td>Masa aktif (hari)</td></tr>
    <tr><td>limitip</td><td><span class="opt">opsional</span></td><td>Maks IP (default: 1)</td></tr></table>
    <div class="url-box"><button class="cp" onclick="cp(this)">Copy</button>${baseUrl}/api/create-ssh?auth=${auth}&amp;user=myuser&amp;password=mypass&amp;exp=30&amp;limitip=2</div>
    <div class="rb">{
  "status": "success",
  "data": {
    "username": "myuser",
    "password": "mypass",
    "host": "${domain}",
    "ip": "x.x.x.x",
    "ports": { ... },
    "formats": {
      "port80":  "${domain}:80@myuser:mypass",
      "port443": "${domain}:443@myuser:mypass",
      "udp":     "${domain}:54-65535@myuser:mypass"
    },
    "ovpnDownload": "https://${domain}:81",
    "saveLink": "https://${domain}:81/ssh-myuser.txt",
    "payloads": { ... },
    "created": "05 Mar, 2026",
    "expired": "30 Days",
    "expiredDate": "04 Apr, 2026",
    "limitIP": "2",
    "isp": "...",
    "city": "..."
  }
}</div>
  </div>
</div>

<!-- ═══ VMess ═══ -->
<div class="sh"><span class="tag t-vm">VMESS</span> VMess (Xray)</div>

<div class="ep">
  <div class="ep-hd" onclick="tog(this)">
    <span class="mth get">GET</span>
    <span class="pth">/api/trial-vmess</span>
    <span class="dsc">Trial VMess 60 menit</span>
    <span class="tag t-trial">TRIAL</span>
  </div>
  <div class="ep-bd">
    <table><tr><th>Parameter</th><th>Status</th><th>Keterangan</th></tr>
    <tr><td>auth</td><td><span class="req">wajib</span></td><td>API auth key</td></tr></table>
    <div class="url-box"><button class="cp" onclick="cp(this)">Copy</button>${baseUrl}/api/trial-vmess?auth=${auth}</div>
    <div class="rb">{
  "status": "success",
  "data": {
    "user": "Trial6150",
    "uuid": "9207a7a0-5d21-4d0f-8e62-a3c23bcb72ba",
    "expired": "60 minutes",
    "domain": "${domain}",
    "ws_tls":      "vmess://eyJ2IjoiMiIs...",
    "ws_none_tls": "vmess://eyJ2IjoiMiIs...",
    "grpc":        "vmess://eyJ2IjoiMiIs...",
    "openclash":   "https://${domain}:81/vmess-Trial6150.txt",
    "dashboard_url": "https://${domain}/api/vmess-Trial6150.html"
  }
}</div>
  </div>
</div>

<div class="ep">
  <div class="ep-hd" onclick="tog(this)">
    <span class="mth get">GET</span>
    <span class="pth">/api/create-vmess</span>
    <span class="dsc">Buat akun VMess</span>
    <span class="tag t-vm">VMESS</span>
  </div>
  <div class="ep-bd">
    <table><tr><th>Parameter</th><th>Status</th><th>Keterangan</th></tr>
    <tr><td>auth</td><td><span class="req">wajib</span></td><td>API auth key</td></tr>
    <tr><td>user</td><td><span class="req">wajib</span></td><td>Username</td></tr>
    <tr><td>exp</td><td><span class="req">wajib</span></td><td>Masa aktif (hari)</td></tr>
    <tr><td>quota</td><td><span class="opt">opsional</span></td><td>Kuota GB (0=unlimited)</td></tr>
    <tr><td>limitip</td><td><span class="opt">opsional</span></td><td>Maks IP (default: 1)</td></tr></table>
    <div class="url-box"><button class="cp" onclick="cp(this)">Copy</button>${baseUrl}/api/create-vmess?auth=${auth}&amp;user=myuser&amp;quota=10&amp;limitip=1&amp;exp=30</div>
    <div class="rb">{
  "status": "success",
  "data": {
    "user": "myuser",
    "uuid": "xxxx-xxxx-xxxx-xxxx",
    "expired": "30 Days",
    "expiredDate": "04 Apr, 2026",
    "domain": "${domain}",
    "quota": "10 GB",
    "limitIP": "1",
    "ws_tls":      "vmess://...",
    "ws_none_tls": "vmess://...",
    "grpc":        "vmess://...",
    "openclash":   "https://${domain}:81/vmess-myuser.txt",
    "dashboard_url": "https://${domain}/api/vmess-myuser.html"
  }
}</div>
  </div>
</div>

<!-- ═══ VLess ═══ -->
<div class="sh"><span class="tag t-vl">VLESS</span> VLess (Xray)</div>

<div class="ep">
  <div class="ep-hd" onclick="tog(this)">
    <span class="mth get">GET</span>
    <span class="pth">/api/trial-vless</span>
    <span class="dsc">Trial VLess 60 menit</span>
    <span class="tag t-trial">TRIAL</span>
  </div>
  <div class="ep-bd">
    <table><tr><th>Parameter</th><th>Status</th><th>Keterangan</th></tr>
    <tr><td>auth</td><td><span class="req">wajib</span></td><td>API auth key</td></tr></table>
    <div class="url-box"><button class="cp" onclick="cp(this)">Copy</button>${baseUrl}/api/trial-vless?auth=${auth}</div>
    <div class="rb">{
  "status": "success",
  "data": {
    "user": "Trial6813",
    "uuid": "2a29fc9b-2f27-417a-88e4-323b9b1e9ede",
    "expired": "60 minutes",
    "domain": "${domain}",
    "ws_tls":      "vless://2a29fc9b...@${domain}:443?path=%2Fvless&security=tls...",
    "ws_none_tls": "vless://2a29fc9b...@${domain}:80?path=%2Fvless...",
    "grpc":        "vless://2a29fc9b...@${domain}:443?mode=gun&security=tls...",
    "openclash":   "https://${domain}:81/vless-Trial6813.txt",
    "dashboard_url": "https://${domain}/api/vless-Trial6813.html"
  }
}</div>
  </div>
</div>

<div class="ep">
  <div class="ep-hd" onclick="tog(this)">
    <span class="mth get">GET</span>
    <span class="pth">/api/create-vless</span>
    <span class="dsc">Buat akun VLess</span>
    <span class="tag t-vl">VLESS</span>
  </div>
  <div class="ep-bd">
    <table><tr><th>Parameter</th><th>Status</th><th>Keterangan</th></tr>
    <tr><td>auth</td><td><span class="req">wajib</span></td><td>API auth key</td></tr>
    <tr><td>user</td><td><span class="req">wajib</span></td><td>Username</td></tr>
    <tr><td>exp</td><td><span class="req">wajib</span></td><td>Masa aktif (hari)</td></tr>
    <tr><td>quota</td><td><span class="opt">opsional</span></td><td>Kuota GB</td></tr>
    <tr><td>limitip</td><td><span class="opt">opsional</span></td><td>Maks IP</td></tr></table>
    <div class="url-box"><button class="cp" onclick="cp(this)">Copy</button>${baseUrl}/api/create-vless?auth=${auth}&amp;user=myuser&amp;quota=10&amp;limitip=1&amp;exp=30</div>
    <div class="rb">{
  "status": "success",
  "data": {
    "user": "myuser",
    "uuid": "xxxx-xxxx-xxxx-xxxx",
    "expired": "30 Days",
    "expiredDate": "04 Apr, 2026",
    "domain": "${domain}",
    "quota": "10 GB",
    "limitIP": "1",
    "ws_tls":      "vless://...",
    "ws_none_tls": "vless://...",
    "grpc":        "vless://...",
    "openclash":   "https://${domain}:81/vless-myuser.txt",
    "dashboard_url": "https://${domain}/api/vless-myuser.html"
  }
}</div>
  </div>
</div>

<!-- ═══ Trojan ═══ -->
<div class="sh"><span class="tag t-tr">TROJAN</span> Trojan (Xray)</div>

<div class="ep">
  <div class="ep-hd" onclick="tog(this)">
    <span class="mth get">GET</span>
    <span class="pth">/api/trial-trojan</span>
    <span class="dsc">Trial Trojan 60 menit</span>
    <span class="tag t-trial">TRIAL</span>
  </div>
  <div class="ep-bd">
    <table><tr><th>Parameter</th><th>Status</th><th>Keterangan</th></tr>
    <tr><td>auth</td><td><span class="req">wajib</span></td><td>API auth key</td></tr></table>
    <div class="url-box"><button class="cp" onclick="cp(this)">Copy</button>${baseUrl}/api/trial-trojan?auth=${auth}</div>
    <div class="rb">{
  "status": "success",
  "data": {
    "user": "Trial7804",
    "uuid": "71e0605c-0351-4d8c-a31a-62bc33ae6bba",
    "expired": "60 minutes",
    "domain": "${domain}",
    "ws":   "trojan://71e0605c...@${domain}:443?path=%2Ftrojan-ws&security=tls...",
    "grpc": "trojan://71e0605c...@${domain}:443?mode=gun&security=tls...",
    "openclash":   "https://${domain}:81/trojan-Trial7804.txt",
    "dashboard_url": "https://${domain}/api/trojan-Trial7804.html"
  }
}</div>
  </div>
</div>

<div class="ep">
  <div class="ep-hd" onclick="tog(this)">
    <span class="mth get">GET</span>
    <span class="pth">/api/create-trojan</span>
    <span class="dsc">Buat akun Trojan</span>
    <span class="tag t-tr">TROJAN</span>
  </div>
  <div class="ep-bd">
    <table><tr><th>Parameter</th><th>Status</th><th>Keterangan</th></tr>
    <tr><td>auth</td><td><span class="req">wajib</span></td><td>API auth key</td></tr>
    <tr><td>user</td><td><span class="req">wajib</span></td><td>Username</td></tr>
    <tr><td>exp</td><td><span class="req">wajib</span></td><td>Masa aktif (hari)</td></tr>
    <tr><td>quota</td><td><span class="opt">opsional</span></td><td>Kuota GB</td></tr>
    <tr><td>limitip</td><td><span class="opt">opsional</span></td><td>Maks IP</td></tr></table>
    <div class="url-box"><button class="cp" onclick="cp(this)">Copy</button>${baseUrl}/api/create-trojan?auth=${auth}&amp;user=myuser&amp;quota=10&amp;limitip=1&amp;exp=30</div>
    <div class="rb">{
  "status": "success",
  "data": {
    "user": "myuser",
    "uuid": "xxxx-xxxx-xxxx-xxxx",
    "expired": "30 Days",
    "expiredDate": "04 Apr, 2026",
    "domain": "${domain}",
    "quota": "10 GB",
    "limitIP": "1",
    "ws":   "trojan://...",
    "grpc": "trojan://...",
    "openclash":   "https://${domain}:81/trojan-myuser.txt",
    "dashboard_url": "https://${domain}/api/trojan-myuser.html"
  }
}</div>
  </div>
</div>

<div class="ftr">NEXUSDEV · HTTPS via Nginx · <a href="https://t.me/nexusdev">@nexusdev</a></div>
</div>
<script>
function tog(el){el.nextElementSibling.classList.toggle('open')}
function cp(btn){
  const t=btn.parentElement.textContent.trim().replace('Copy','').trim();
  navigator.clipboard.writeText(t).then(()=>{btn.textContent='✓ Copied!';setTimeout(()=>btn.textContent='Copy',1600)});
}
</script>
</body></html>`;
  sendHTML(res, html);
}

// ─── Server & Router ─────────────────────────────────────────────────────────

const server = http.createServer((req, res) => {
  const parsed   = url.parse(req.url, true);
  const pathname = parsed.pathname;
  const params   = parsed.query;

  // Doc page — no auth needed
  if (pathname === '/api/doc.html') return handleDocPage(res);

  // Auth check
  if (pathname.startsWith('/api/')) {
    const stored = getAuth();
    if (stored && params.auth !== stored)
      return sendJSON(res, 403, { status: 'error', message: 'Invalid or missing auth key' });
  }

  // Routes
  if (pathname === '/api/trial-ssh')     return handleTrialSSH(params, res);
  if (pathname === '/api/create-ssh')    return handleCreateSSH(params, res);
  if (pathname === '/api/trial-vmess')   return handleTrialVmess(params, res);
  if (pathname === '/api/create-vmess')  return handleCreateVmess(params, res);
  if (pathname === '/api/trial-vless')   return handleTrialVless(params, res);
  if (pathname === '/api/create-vless')  return handleCreateVless(params, res);
  if (pathname === '/api/trial-trojan')  return handleTrialTrojan(params, res);
  if (pathname === '/api/create-trojan') return handleCreateTrojan(params, res);

  sendJSON(res, 404, { status: 'error', message: `Not found: ${pathname} — see /api/doc.html` });
});

server.listen(PORT, HOST, () => {
  console.log(`[NEXUSDEV API] Listening on ${HOST}:${PORT}`);
  console.log(`[NEXUSDEV API] Proxied via Nginx → https://${getDomain()}/api/`);
});
