/**
 * ARISCTUNNEL V4 - REST API Service
 * Supports: SSH, VMess, VLess, Trojan (Create & Trial)
 * Port: 7979
 */

const http = require('http');
const https = require('https');
const fs = require('fs');
const url = require('url');

const PORT = 7979;
const AUTH_KEY_PATH = '/etc/ssh/api_auth.key';

// ─── Helpers ───────────────────────────────────────────────────────────────

function readFile(path, fallback = '') {
  try { return fs.readFileSync(path, 'utf8').trim(); } catch { return fallback; }
}

function getAuth() {
  return readFile(AUTH_KEY_PATH, '');
}

function getDomain() {
  return readFile('/etc/xray/domain', 'yourdomain.com');
}

function getIP() {
  return readFile('/usr/bin/ipsave', '');
}

function getISP() {
  return readFile('/etc/xray/isp', '');
}

function getCity() {
  return readFile('/etc/xray/city', '');
}

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
  const months = ['Jan','Feb','Mar','Apr','May','Jun','Jul','Aug','Sep','Oct','Nov','Dec'];
  return `${String(d.getDate()).padStart(2,'0')} ${months[d.getMonth()]}, ${d.getFullYear()}`;
}

function formatDateFull(d) {
  const months = ['Jan','Feb','Mar','Apr','May','Jun','Jul','Aug','Sep','Oct','Nov','Dec'];
  return `${months[d.getMonth()]} ${d.getDate()}, ${d.getFullYear()}`;
}

function sendJSON(res, statusCode, data) {
  res.writeHead(statusCode, { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*' });
  res.end(JSON.stringify(data, null, 2));
}

function sendHTML(res, html) {
  res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8', 'Access-Control-Allow-Origin': '*' });
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

// ─── SSH Handler ────────────────────────────────────────────────────────────

function handleCreateSSH(params, res) {
  const { user, password, exp, limitip } = params;
  if (!user || !password || !exp) {
    return sendJSON(res, 400, { status: 'error', message: 'Required: user, password, exp' });
  }

  const domain = getDomain();
  const ip = getIP();
  const isp = getISP();
  const city = getCity();
  const iplimit = limitip || '1';
  const expDate = dateAfterDays(exp);
  const expStr = formatDateShort(expDate);
  const expISO = expDate.toISOString().split('T')[0];
  const createdStr = formatDateShort(new Date());

  // Create system user
  execCmd(`useradd -e "${expISO}" -s /bin/false -M "${user}" 2>/dev/null || true`);
  execCmd(`echo "${password}:${password}" | chpasswd 2>/dev/null || echo -e "${password}\\n${password}" | passwd "${user}" 2>/dev/null || true`);
  if (parseInt(iplimit) > 0) {
    execCmd(`mkdir -p /etc/kyt/limit/ssh/ip && echo "${iplimit}" > /etc/kyt/limit/ssh/ip/${user}`);
  }
  // Add to DB
  execCmd(`grep -v "^#ssh# ${user} " /etc/ssh/.ssh.db > /tmp/ssh.db.tmp 2>/dev/null && mv /tmp/ssh.db.tmp /etc/ssh/.ssh.db || true`);
  execCmd(`echo "#ssh# ${user} ${password} 0 ${iplimit} ${expStr}" >> /etc/ssh/.ssh.db`);

  // Save account file
  const txtContent = `==============================
Format SSH OVPN Account
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
==============================
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
        port80: `${domain}:80@${user}:${password}`,
        port443: `${domain}:443@${user}:${password}`,
        udp: `${domain}:54-65535@${user}:${password}`
      },
      ovpnDownload: `https://${domain}:81`,
      saveLink: `https://${domain}:81/ssh-${user}.txt`,
      payloads: {
        wsNtls: `GET / HTTP/1.1[crlf]Host: [host][crlf]Connection: Upgrade[crlf]User-Agent: [ua][crlf]Upgrade: ws[crlf][crlf]`,
        wsTls: `GET wss://${domain}/ HTTP/1.1[crlf]Host: [host][crlf]Connection: Upgrade[crlf]User-Agent: [ua][crlf]Upgrade: ws[crlf][crlf]`,
        enhanced: `PATCH / HTTP/1.1[crlf]Host: ${domain}[crlf]Host: bug.com[crlf]Upgrade: websocket[crlf]Connection: Upgrade[crlf][crlf]`
      },
      created: createdStr,
      expired: `${exp} Days`,
      expiredDate: expStr,
      limitIP: iplimit,
      isp: isp,
      city: city
    }
  });
}

function handleTrialSSH(params, res) {
  const domain = getDomain();
  const ip = getIP();
  const isp = getISP();
  const city = getCity();
  const randNum = randomNum(10000, 99999);
  const user = `Trial${randNum}`;
  const password = '1';
  const iplimit = '99';
  const expDate = dateAfterDays(0);
  const expStr = formatDateShort(expDate);
  const expISO = expDate.toISOString().split('T')[0];
  const createdStr = formatDateShort(new Date());

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
        port80: `${domain}:80@${user}:${password}`,
        port443: `${domain}:443@${user}:${password}`,
        udp: `${domain}:54-65535@${user}:${password}`
      },
      ovpnDownload: `https://${domain}:81`,
      saveLink: `https://${domain}:81/ssh-${user}.txt`,
      payloads: {
        wsNtls: `GET / HTTP/1.1[crlf]Host: [host][crlf]Connection: Upgrade[crlf]User-Agent: [ua][crlf]Upgrade: ws[crlf][crlf]`,
        wsTls: `GET wss://${domain}/ HTTP/1.1[crlf]Host: [host][crlf]Connection: Upgrade[crlf]User-Agent: [ua][crlf]Upgrade: ws[crlf][crlf]`,
        enhanced: `PATCH / HTTP/1.1[crlf]Host: ${domain}[crlf]Host: bug.com[crlf]Upgrade: websocket[crlf]Connection: Upgrade[crlf][crlf]`
      },
      created: createdStr,
      expired: '60 Minutes',
      isp: isp,
      city: city
    }
  });
}

// ─── VMess Handler ──────────────────────────────────────────────────────────

function buildVmessLinks(user, uuid, domain) {
  const wsTlsObj = { v:'2', ps:`${user}-TLS`, add:domain, port:'443', id:uuid, aid:'0', net:'ws', type:'none', host:domain, path:'/vmess', tls:'tls' };
  const wsNtlsObj = { v:'2', ps:`${user}-NoneTLS`, add:domain, port:'80', id:uuid, aid:'0', net:'ws', type:'none', host:domain, path:'/vmess', tls:'none' };
  const grpcObj = { v:'2', ps:`${user}-gRPC`, add:domain, port:'443', id:uuid, aid:'0', net:'grpc', type:'none', host:'', path:'vmess-grpc', tls:'tls' };
  return {
    ws_tls: `vmess://${Buffer.from(JSON.stringify(wsTlsObj)).toString('base64')}`,
    ws_none_tls: `vmess://${Buffer.from(JSON.stringify(wsNtlsObj)).toString('base64')}`,
    grpc: `vmess://${Buffer.from(JSON.stringify(grpcObj)).toString('base64')}`
  };
}

function handleCreateVmess(params, res) {
  const { user, quota, limitip, exp } = params;
  if (!user || !exp) return sendJSON(res, 400, { status: 'error', message: 'Required: user, exp' });

  const domain = getDomain();
  const uuid = genUUID();
  const expDate = dateAfterDays(exp);
  const expISO = expDate.toISOString().split('T')[0];
  const expStr = formatDateShort(expDate);
  const iplimit = limitip || '1';
  const links = buildVmessLinks(user, uuid, domain);

  // Add to xray config
  execCmd(`sed -i '/#vmess$/a\\### ${user} ${expISO}\\\\\\n},{\"id\": \"${uuid}\",\"alterId\": 0,\"email\": \"${user}\"' /etc/xray/config.json 2>/dev/null || true`);
  execCmd(`sed -i '/#vmessgrpc$/a\\### ${user} ${expISO}\\\\\\n},{\"id\": \"${uuid}\",\"alterId\": 0,\"email\": \"${user}\"' /etc/xray/config.json 2>/dev/null || true`);
  if (parseInt(iplimit) > 0) execCmd(`mkdir -p /etc/kyt/limit/vmess/ip && echo "${iplimit}" > /etc/kyt/limit/vmess/ip/${user}`);
  execCmd(`grep -v "^### ${user} " /etc/vmess/.vmess.db > /tmp/vm.tmp 2>/dev/null && mv /tmp/vm.tmp /etc/vmess/.vmess.db || true`);
  execCmd(`echo "### ${user} ${expISO} ${uuid} ${quota||0} ${iplimit}" >> /etc/vmess/.vmess.db`);
  execCmd(`systemctl restart xray 2>/dev/null || true`);

  sendJSON(res, 200, {
    status: 'success',
    data: {
      user: user,
      uuid: uuid,
      expired: `${exp} Days`,
      expiredDate: expStr,
      domain: domain,
      quota: `${quota || 0} GB`,
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
  const domain = getDomain();
  const randNum = randomNum(1000, 9999);
  const user = `Trial${randNum}`;
  const uuid = genUUID();
  const expDate = dateAfterDays(0);
  const expISO = expDate.toISOString().split('T')[0];
  const links = buildVmessLinks(user, uuid, domain);

  execCmd(`sed -i '/#vmess$/a\\### ${user} ${expISO}\\\\\\n},{\"id\": \"${uuid}\",\"alterId\": 0,\"email\": \"${user}\"' /etc/xray/config.json 2>/dev/null || true`);
  execCmd(`sed -i '/#vmessgrpc$/a\\### ${user} ${expISO}\\\\\\n},{\"id\": \"${uuid}\",\"alterId\": 0,\"email\": \"${user}\"' /etc/xray/config.json 2>/dev/null || true`);
  execCmd(`systemctl restart xray 2>/dev/null || true`);

  sendJSON(res, 200, {
    status: 'success',
    data: {
      user: user,
      uuid: uuid,
      expired: '60 minutes',
      domain: domain,
      ws_tls: links.ws_tls,
      ws_none_tls: links.ws_none_tls,
      grpc: links.grpc,
      openclash: `https://${domain}:81/vmess-${user}.txt`,
      dashboard_url: `https://${domain}/api/vmess-${user}.html`
    }
  });
}

// ─── VLess Handler ──────────────────────────────────────────────────────────

function buildVlessLinks(user, uuid, domain) {
  return {
    ws_tls: `vless://${uuid}@${domain}:443?path=%2Fvless&security=tls&encryption=none&type=ws#${user}-TLS`,
    ws_none_tls: `vless://${uuid}@${domain}:80?path=%2Fvless&encryption=none&type=ws#${user}-NoneTLS`,
    grpc: `vless://${uuid}@${domain}:443?mode=gun&security=tls&encryption=none&type=grpc&serviceName=vless-grpc&sni=${domain}#${user}-gRPC`
  };
}

function handleCreateVless(params, res) {
  const { user, quota, limitip, exp } = params;
  if (!user || !exp) return sendJSON(res, 400, { status: 'error', message: 'Required: user, exp' });

  const domain = getDomain();
  const uuid = genUUID();
  const expDate = dateAfterDays(exp);
  const expISO = expDate.toISOString().split('T')[0];
  const expStr = formatDateShort(expDate);
  const iplimit = limitip || '1';
  const links = buildVlessLinks(user, uuid, domain);

  execCmd(`sed -i '/#vless$/a\\#& ${user} ${expISO}\\\\\\n},{\"id\": \"${uuid}\",\"email\": \"${user}\"' /etc/xray/config.json 2>/dev/null || true`);
  execCmd(`sed -i '/#vlessgrpc$/a\\#& ${user} ${expISO}\\\\\\n},{\"id\": \"${uuid}\",\"email\": \"${user}\"' /etc/xray/config.json 2>/dev/null || true`);
  if (parseInt(iplimit) > 0) execCmd(`mkdir -p /etc/kyt/limit/vless/ip && echo "${iplimit}" > /etc/kyt/limit/vless/ip/${user}`);
  execCmd(`grep -v "^#& ${user} " /etc/vless/.vless.db > /tmp/vl.tmp 2>/dev/null && mv /tmp/vl.tmp /etc/vless/.vless.db || true`);
  execCmd(`echo "#& ${user} ${expISO} ${uuid} ${quota||0} ${iplimit}" >> /etc/vless/.vless.db`);
  execCmd(`systemctl restart xray 2>/dev/null || true`);

  sendJSON(res, 200, {
    status: 'success',
    data: {
      user: user,
      uuid: uuid,
      expired: `${exp} Days`,
      expiredDate: expStr,
      domain: domain,
      quota: `${quota || 0} GB`,
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
  const domain = getDomain();
  const randNum = randomNum(1000, 9999);
  const user = `Trial${randNum}`;
  const uuid = genUUID();
  const expDate = dateAfterDays(0);
  const expISO = expDate.toISOString().split('T')[0];
  const links = buildVlessLinks(user, uuid, domain);

  execCmd(`sed -i '/#vless$/a\\#& ${user} ${expISO}\\\\\\n},{\"id\": \"${uuid}\",\"email\": \"${user}\"' /etc/xray/config.json 2>/dev/null || true`);
  execCmd(`sed -i '/#vlessgrpc$/a\\#& ${user} ${expISO}\\\\\\n},{\"id\": \"${uuid}\",\"email\": \"${user}\"' /etc/xray/config.json 2>/dev/null || true`);
  execCmd(`systemctl restart xray 2>/dev/null || true`);

  sendJSON(res, 200, {
    status: 'success',
    data: {
      user: user,
      uuid: uuid,
      expired: '60 minutes',
      domain: domain,
      ws_tls: links.ws_tls,
      ws_none_tls: links.ws_none_tls,
      grpc: links.grpc,
      openclash: `https://${domain}:81/vless-${user}.txt`,
      dashboard_url: `https://${domain}/api/vless-${user}.html`
    }
  });
}

// ─── Trojan Handler ─────────────────────────────────────────────────────────

function buildTrojanLinks(user, uuid, domain) {
  return {
    ws: `trojan://${uuid}@${domain}:443?path=%2Ftrojan-ws&security=tls&host=${domain}&type=ws&sni=${domain}#${user}`,
    grpc: `trojan://${uuid}@${domain}:443?mode=gun&security=tls&type=grpc&serviceName=trojan-grpc&sni=${domain}#${user}`
  };
}

function handleCreateTrojan(params, res) {
  const { user, quota, limitip, exp } = params;
  if (!user || !exp) return sendJSON(res, 400, { status: 'error', message: 'Required: user, exp' });

  const domain = getDomain();
  const uuid = genUUID();
  const expDate = dateAfterDays(exp);
  const expISO = expDate.toISOString().split('T')[0];
  const expStr = formatDateShort(expDate);
  const iplimit = limitip || '1';
  const links = buildTrojanLinks(user, uuid, domain);

  execCmd(`sed -i '/#trojanws$/a\\#! ${user} ${expISO}\\\\\\n},{\"password\": \"${uuid}\",\"email\": \"${user}\"' /etc/xray/config.json 2>/dev/null || true`);
  execCmd(`sed -i '/#trojangrpc$/a\\#! ${user} ${expISO}\\\\\\n},{\"password\": \"${uuid}\",\"email\": \"${user}\"' /etc/xray/config.json 2>/dev/null || true`);
  if (parseInt(iplimit) > 0) execCmd(`mkdir -p /etc/kyt/limit/trojan/ip && echo "${iplimit}" > /etc/kyt/limit/trojan/ip/${user}`);
  execCmd(`grep -v "^### ${user} " /etc/trojan/.trojan.db > /tmp/tr.tmp 2>/dev/null && mv /tmp/tr.tmp /etc/trojan/.trojan.db || true`);
  execCmd(`echo "### ${user} ${expISO} ${uuid} ${quota||0} ${iplimit}" >> /etc/trojan/.trojan.db`);
  execCmd(`systemctl restart xray 2>/dev/null || true`);

  sendJSON(res, 200, {
    status: 'success',
    data: {
      user: user,
      uuid: uuid,
      expired: `${exp} Days`,
      expiredDate: expStr,
      domain: domain,
      quota: `${quota || 0} GB`,
      limitIP: iplimit,
      ws: links.ws,
      grpc: links.grpc,
      openclash: `https://${domain}:81/trojan-${user}.txt`,
      dashboard_url: `https://${domain}/api/trojan-${user}.html`
    }
  });
}

function handleTrialTrojan(params, res) {
  const domain = getDomain();
  const randNum = randomNum(1000, 9999);
  const user = `Trial${randNum}`;
  const uuid = genUUID();
  const expDate = dateAfterDays(0);
  const expISO = expDate.toISOString().split('T')[0];
  const links = buildTrojanLinks(user, uuid, domain);

  execCmd(`sed -i '/#trojanws$/a\\#! ${user} ${expISO}\\\\\\n},{\"password\": \"${uuid}\",\"email\": \"${user}\"' /etc/xray/config.json 2>/dev/null || true`);
  execCmd(`sed -i '/#trojangrpc$/a\\#! ${user} ${expISO}\\\\\\n},{\"password\": \"${uuid}\",\"email\": \"${user}\"' /etc/xray/config.json 2>/dev/null || true`);
  execCmd(`systemctl restart xray 2>/dev/null || true`);

  sendJSON(res, 200, {
    status: 'success',
    data: {
      user: user,
      uuid: uuid,
      expired: '60 minutes',
      domain: domain,
      ws: links.ws,
      grpc: links.grpc,
      openclash: `https://${domain}:81/trojan-${user}.txt`,
      dashboard_url: `https://${domain}/api/trojan-${user}.html`
    }
  });
}

// ─── API Docs Page ──────────────────────────────────────────────────────────

function handleDocPage(domain, res) {
  const auth = getAuth();
  const html = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>ARISCTUNNEL V4 - API Documentation</title>
<style>
* { box-sizing: border-box; margin: 0; padding: 0; }
body { font-family: 'Segoe UI', sans-serif; background: #0d1117; color: #e6edf3; min-height: 100vh; }
.header { background: linear-gradient(135deg, #161b22, #21262d); border-bottom: 1px solid #30363d; padding: 24px 32px; display: flex; align-items: center; gap: 16px; }
.header h1 { font-size: 1.5rem; color: #58a6ff; }
.header span { background: #238636; color: #fff; padding: 3px 10px; border-radius: 12px; font-size: 0.75rem; font-weight: 600; }
.container { max-width: 1100px; margin: 0 auto; padding: 32px 16px; }
.auth-box { background: #161b22; border: 1px solid #f0883e66; border-radius: 10px; padding: 20px 24px; margin-bottom: 32px; display: flex; align-items: center; gap: 12px; }
.auth-box .label { color: #f0883e; font-size: 0.85rem; font-weight: 600; white-space: nowrap; }
.auth-box .key { font-family: monospace; font-size: 1rem; color: #ffa657; word-break: break-all; }
.section-title { font-size: 1.1rem; color: #79c0ff; font-weight: 600; margin: 32px 0 14px; border-left: 3px solid #79c0ff; padding-left: 10px; }
.endpoint { background: #161b22; border: 1px solid #30363d; border-radius: 10px; margin-bottom: 14px; overflow: hidden; }
.endpoint-head { display: flex; align-items: center; gap: 10px; padding: 14px 18px; cursor: pointer; user-select: none; }
.endpoint-head:hover { background: #1c2128; }
.method { padding: 3px 10px; border-radius: 5px; font-size: 0.75rem; font-weight: 700; min-width: 50px; text-align: center; }
.get { background: #1a7f37; color: #aff5b4; }
.post { background: #1461a8; color: #a5d6ff; }
.path { font-family: monospace; font-size: 0.9rem; color: #e6edf3; flex: 1; }
.desc { font-size: 0.8rem; color: #8b949e; }
.endpoint-body { display: none; padding: 18px; border-top: 1px solid #21262d; background: #0d1117; }
.endpoint-body.open { display: block; }
.params-table { width: 100%; border-collapse: collapse; font-size: 0.85rem; margin-bottom: 16px; }
.params-table th { background: #161b22; color: #8b949e; text-align: left; padding: 8px 12px; }
.params-table td { border-top: 1px solid #21262d; padding: 8px 12px; }
.required { color: #f85149; font-weight: 600; font-size: 0.75rem; }
.optional { color: #3fb950; font-size: 0.75rem; }
.example-url { background: #161b22; border: 1px solid #30363d; border-radius: 6px; padding: 10px 14px; font-family: monospace; font-size: 0.8rem; color: #79c0ff; word-break: break-all; margin-bottom: 12px; }
.response-box { background: #161b22; border: 1px solid #30363d; border-radius: 6px; padding: 14px; font-family: monospace; font-size: 0.8rem; white-space: pre-wrap; color: #aff5b4; max-height: 360px; overflow-y: auto; }
.copy-btn { background: #21262d; border: 1px solid #30363d; color: #8b949e; padding: 4px 10px; border-radius: 5px; cursor: pointer; font-size: 0.75rem; float: right; }
.copy-btn:hover { background: #30363d; color: #e6edf3; }
.tag { font-size: 0.7rem; padding: 2px 8px; border-radius: 8px; font-weight: 600; margin-left: 4px; }
.tag-ssh { background: #1a7f37; color: #aff5b4; }
.tag-vmess { background: #1461a8; color: #a5d6ff; }
.tag-vless { background: #6e40c9; color: #d2a8ff; }
.tag-trojan { background: #9a1616; color: #ffa198; }
.tag-trial { background: #9e6a03; color: #ffa657; }
</style>
</head>
<body>
<div class="header">
  <div>
    <h1>⚡ ARISCTUNNEL V4 — REST API</h1>
    <div style="margin-top:6px;font-size:0.85rem;color:#8b949e;">Base URL: <span style="color:#79c0ff;font-family:monospace;">http://${domain}:7979</span></div>
  </div>
  <span>v4.0 LTS</span>
</div>
<div class="container">

<div class="auth-box">
  <div class="label">🔑 AUTH KEY:</div>
  <div class="key">${auth || '(not set - check /etc/ssh/api_auth.key)'}</div>
</div>
<p style="color:#8b949e;font-size:0.85rem;margin-bottom:8px;">All endpoints require <code style="color:#ffa657;">?auth=YOUR_KEY</code> as a query parameter.</p>

<!-- SSH -->
<div class="section-title">SSH / OpenVPN <span class="tag tag-ssh">SSH</span></div>

<div class="endpoint">
  <div class="endpoint-head" onclick="toggle(this)">
    <span class="method get">GET</span>
    <span class="path">/api/trial-ssh</span>
    <span class="desc">Create 60-minute trial SSH account</span>
    <span class="tag tag-trial">TRIAL</span>
  </div>
  <div class="endpoint-body">
    <table class="params-table">
      <tr><th>Parameter</th><th>Required</th><th>Description</th></tr>
      <tr><td>auth</td><td><span class="required">required</span></td><td>API authentication key</td></tr>
    </table>
    <div class="example-url">
      <button class="copy-btn" onclick="copyUrl(this)">Copy</button>
      http://${domain}:7979/api/trial-ssh?auth=${auth}
    </div>
    <div class="response-box">{
  "status": "success",
  "data": {
    "username": "Trial64897",
    "password": "1",
    "host": "${domain}",
    "ip": "x.x.x.x",
    "ports": { "openSSH": "22", "dropbear": "143, 109", "sshUDP": "1-65535", ... },
    "formats": {
      "port80": "${domain}:80@Trial64897:1",
      "port443": "${domain}:443@Trial64897:1",
      "udp": "${domain}:54-65535@Trial64897:1"
    },
    "ovpnDownload": "https://${domain}:81",
    "saveLink": "https://${domain}:81/ssh-Trial64897.txt",
    "payloads": { "wsNtls": "GET / HTTP/1.1[crlf]...", "wsTls": "...", "enhanced": "..." },
    "created": "05 Mar, 2026",
    "expired": "60 Minutes",
    "isp": "...",
    "city": "..."
  }
}</div>
  </div>
</div>

<div class="endpoint">
  <div class="endpoint-head" onclick="toggle(this)">
    <span class="method get">GET</span>
    <span class="path">/api/create-ssh</span>
    <span class="desc">Create SSH account with custom settings</span>
    <span class="tag tag-ssh">SSH</span>
  </div>
  <div class="endpoint-body">
    <table class="params-table">
      <tr><th>Parameter</th><th>Required</th><th>Description</th></tr>
      <tr><td>auth</td><td><span class="required">required</span></td><td>API authentication key</td></tr>
      <tr><td>user</td><td><span class="required">required</span></td><td>Username</td></tr>
      <tr><td>password</td><td><span class="required">required</span></td><td>Password</td></tr>
      <tr><td>exp</td><td><span class="required">required</span></td><td>Expiry in days</td></tr>
      <tr><td>limitip</td><td><span class="optional">optional</span></td><td>Max IP connections (default: 1)</td></tr>
    </table>
    <div class="example-url">
      <button class="copy-btn" onclick="copyUrl(this)">Copy</button>
      http://${domain}:7979/api/create-ssh?auth=${auth}&amp;user=myuser&amp;password=mypass&amp;exp=30&amp;limitip=2
    </div>
    <div class="response-box">{
  "status": "success",
  "data": {
    "username": "myuser",
    "password": "mypass",
    "host": "${domain}",
    "ip": "x.x.x.x",
    "ports": { ... },
    "formats": { "port80": "...", "port443": "...", "udp": "..." },
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

<!-- VMess -->
<div class="section-title">VMess (Xray) <span class="tag tag-vmess">VMESS</span></div>

<div class="endpoint">
  <div class="endpoint-head" onclick="toggle(this)">
    <span class="method get">GET</span>
    <span class="path">/api/trial-vmess</span>
    <span class="desc">Create 60-minute trial VMess account</span>
    <span class="tag tag-trial">TRIAL</span>
  </div>
  <div class="endpoint-body">
    <table class="params-table">
      <tr><th>Parameter</th><th>Required</th><th>Description</th></tr>
      <tr><td>auth</td><td><span class="required">required</span></td><td>API authentication key</td></tr>
    </table>
    <div class="example-url">
      <button class="copy-btn" onclick="copyUrl(this)">Copy</button>
      http://${domain}:7979/api/trial-vmess?auth=${auth}
    </div>
    <div class="response-box">{
  "status": "success",
  "data": {
    "user": "Trial6150",
    "uuid": "9207a7a0-5d21-4d0f-8e62-a3c23bcb72ba",
    "expired": "60 minutes",
    "domain": "${domain}",
    "ws_tls": "vmess://eyJ2Ijo...",
    "ws_none_tls": "vmess://eyJ2Ijo...",
    "grpc": "vmess://eyJ2Ijo...",
    "openclash": "https://${domain}:81/vmess-Trial6150.txt",
    "dashboard_url": "https://${domain}/api/vmess-Trial6150.html"
  }
}</div>
  </div>
</div>

<div class="endpoint">
  <div class="endpoint-head" onclick="toggle(this)">
    <span class="method get">GET</span>
    <span class="path">/api/create-vmess</span>
    <span class="desc">Create VMess account with custom settings</span>
    <span class="tag tag-vmess">VMESS</span>
  </div>
  <div class="endpoint-body">
    <table class="params-table">
      <tr><th>Parameter</th><th>Required</th><th>Description</th></tr>
      <tr><td>auth</td><td><span class="required">required</span></td><td>API authentication key</td></tr>
      <tr><td>user</td><td><span class="required">required</span></td><td>Username</td></tr>
      <tr><td>exp</td><td><span class="required">required</span></td><td>Expiry in days</td></tr>
      <tr><td>quota</td><td><span class="optional">optional</span></td><td>Data quota in GB (0 = unlimited)</td></tr>
      <tr><td>limitip</td><td><span class="optional">optional</span></td><td>Max IP connections (default: 1)</td></tr>
    </table>
    <div class="example-url">
      <button class="copy-btn" onclick="copyUrl(this)">Copy</button>
      http://${domain}:7979/api/create-vmess?auth=${auth}&amp;user=myuser&amp;quota=10&amp;limitip=1&amp;exp=30
    </div>
    <div class="response-box">{
  "status": "success",
  "data": {
    "user": "myuser",
    "uuid": "xxxx-xxxx-xxxx",
    "expired": "30 Days",
    "expiredDate": "04 Apr, 2026",
    "domain": "${domain}",
    "quota": "10 GB",
    "limitIP": "1",
    "ws_tls": "vmess://...",
    "ws_none_tls": "vmess://...",
    "grpc": "vmess://...",
    "openclash": "https://${domain}:81/vmess-myuser.txt",
    "dashboard_url": "https://${domain}/api/vmess-myuser.html"
  }
}</div>
  </div>
</div>

<!-- VLess -->
<div class="section-title">VLess (Xray) <span class="tag tag-vless">VLESS</span></div>

<div class="endpoint">
  <div class="endpoint-head" onclick="toggle(this)">
    <span class="method get">GET</span>
    <span class="path">/api/trial-vless</span>
    <span class="desc">Create 60-minute trial VLess account</span>
    <span class="tag tag-trial">TRIAL</span>
  </div>
  <div class="endpoint-body">
    <table class="params-table">
      <tr><th>Parameter</th><th>Required</th><th>Description</th></tr>
      <tr><td>auth</td><td><span class="required">required</span></td><td>API authentication key</td></tr>
    </table>
    <div class="example-url">
      <button class="copy-btn" onclick="copyUrl(this)">Copy</button>
      http://${domain}:7979/api/trial-vless?auth=${auth}
    </div>
    <div class="response-box">{
  "status": "success",
  "data": {
    "user": "Trial6813",
    "uuid": "2a29fc9b-2f27-417a-88e4-323b9b1e9ede",
    "expired": "60 minutes",
    "domain": "${domain}",
    "ws_tls": "vless://2a29fc9b...@${domain}:443?path=%2Fvless&security=tls...",
    "ws_none_tls": "vless://2a29fc9b...@${domain}:80?path=%2Fvless...",
    "grpc": "vless://2a29fc9b...@${domain}:443?mode=gun&security=tls...",
    "openclash": "https://${domain}:81/vless-Trial6813.txt",
    "dashboard_url": "https://${domain}/api/vless-Trial6813.html"
  }
}</div>
  </div>
</div>

<div class="endpoint">
  <div class="endpoint-head" onclick="toggle(this)">
    <span class="method get">GET</span>
    <span class="path">/api/create-vless</span>
    <span class="desc">Create VLess account with custom settings</span>
    <span class="tag tag-vless">VLESS</span>
  </div>
  <div class="endpoint-body">
    <table class="params-table">
      <tr><th>Parameter</th><th>Required</th><th>Description</th></tr>
      <tr><td>auth</td><td><span class="required">required</span></td><td>API authentication key</td></tr>
      <tr><td>user</td><td><span class="required">required</span></td><td>Username</td></tr>
      <tr><td>exp</td><td><span class="required">required</span></td><td>Expiry in days</td></tr>
      <tr><td>quota</td><td><span class="optional">optional</span></td><td>Data quota in GB</td></tr>
      <tr><td>limitip</td><td><span class="optional">optional</span></td><td>Max IP connections</td></tr>
    </table>
    <div class="example-url">
      <button class="copy-btn" onclick="copyUrl(this)">Copy</button>
      http://${domain}:7979/api/create-vless?auth=${auth}&amp;user=myuser&amp;quota=10&amp;limitip=1&amp;exp=30
    </div>
    <div class="response-box">{
  "status": "success",
  "data": {
    "user": "myuser",
    "uuid": "xxxx-xxxx-xxxx",
    "expired": "30 Days",
    "expiredDate": "04 Apr, 2026",
    "domain": "${domain}",
    "quota": "10 GB",
    "limitIP": "1",
    "ws_tls": "vless://...",
    "ws_none_tls": "vless://...",
    "grpc": "vless://...",
    "openclash": "https://${domain}:81/vless-myuser.txt",
    "dashboard_url": "https://${domain}/api/vless-myuser.html"
  }
}</div>
  </div>
</div>

<!-- Trojan -->
<div class="section-title">Trojan (Xray) <span class="tag tag-trojan">TROJAN</span></div>

<div class="endpoint">
  <div class="endpoint-head" onclick="toggle(this)">
    <span class="method get">GET</span>
    <span class="path">/api/trial-trojan</span>
    <span class="desc">Create 60-minute trial Trojan account</span>
    <span class="tag tag-trial">TRIAL</span>
  </div>
  <div class="endpoint-body">
    <table class="params-table">
      <tr><th>Parameter</th><th>Required</th><th>Description</th></tr>
      <tr><td>auth</td><td><span class="required">required</span></td><td>API authentication key</td></tr>
    </table>
    <div class="example-url">
      <button class="copy-btn" onclick="copyUrl(this)">Copy</button>
      http://${domain}:7979/api/trial-trojan?auth=${auth}
    </div>
    <div class="response-box">{
  "status": "success",
  "data": {
    "user": "Trial7804",
    "uuid": "71e0605c-0351-4d8c-a31a-62bc33ae6bba",
    "expired": "60 minutes",
    "domain": "${domain}",
    "ws": "trojan://71e0605c...@${domain}:443?path=%2Ftrojan-ws&security=tls...",
    "grpc": "trojan://71e0605c...@${domain}:443?mode=gun&security=tls...",
    "openclash": "https://${domain}:81/trojan-Trial7804.txt",
    "dashboard_url": "https://${domain}/api/trojan-Trial7804.html"
  }
}</div>
  </div>
</div>

<div class="endpoint">
  <div class="endpoint-head" onclick="toggle(this)">
    <span class="method get">GET</span>
    <span class="path">/api/create-trojan</span>
    <span class="desc">Create Trojan account with custom settings</span>
    <span class="tag tag-trojan">TROJAN</span>
  </div>
  <div class="endpoint-body">
    <table class="params-table">
      <tr><th>Parameter</th><th>Required</th><th>Description</th></tr>
      <tr><td>auth</td><td><span class="required">required</span></td><td>API authentication key</td></tr>
      <tr><td>user</td><td><span class="required">required</span></td><td>Username</td></tr>
      <tr><td>exp</td><td><span class="required">required</span></td><td>Expiry in days</td></tr>
      <tr><td>quota</td><td><span class="optional">optional</span></td><td>Data quota in GB</td></tr>
      <tr><td>limitip</td><td><span class="optional">optional</span></td><td>Max IP connections</td></tr>
    </table>
    <div class="example-url">
      <button class="copy-btn" onclick="copyUrl(this)">Copy</button>
      http://${domain}:7979/api/create-trojan?auth=${auth}&amp;user=myuser&amp;quota=10&amp;limitip=1&amp;exp=30
    </div>
    <div class="response-box">{
  "status": "success",
  "data": {
    "user": "myuser",
    "uuid": "xxxx-xxxx-xxxx",
    "expired": "30 Days",
    "expiredDate": "04 Apr, 2026",
    "domain": "${domain}",
    "quota": "10 GB",
    "limitIP": "1",
    "ws": "trojan://...",
    "grpc": "trojan://...",
    "openclash": "https://${domain}:81/trojan-myuser.txt",
    "dashboard_url": "https://${domain}/api/trojan-myuser.html"
  }
}</div>
  </div>
</div>

<div style="text-align:center;color:#484f58;font-size:0.8rem;margin-top:48px;padding-bottom:32px;">
  ARISCTUNNEL V4 · API Port 7979 · <a href="https://t.me/ARI_VPN_STORE" style="color:#58a6ff;">@ARI_VPN_STORE</a>
</div>
</div>
<script>
function toggle(el) {
  const body = el.nextElementSibling;
  body.classList.toggle('open');
}
function copyUrl(btn) {
  const url = btn.parentElement.textContent.trim();
  navigator.clipboard.writeText(url).then(() => { btn.textContent = 'Copied!'; setTimeout(() => btn.textContent = 'Copy', 1500); });
}
</script>
</body>
</html>`;
  sendHTML(res, html);
}

// ─── Router ─────────────────────────────────────────────────────────────────

const server = http.createServer((req, res) => {
  const parsed = url.parse(req.url, true);
  const pathname = parsed.pathname;
  const params = parsed.query;
  const domain = getDomain();

  // Doc page - no auth required
  if (pathname === '/api/doc.html') {
    return handleDocPage(domain, res);
  }

  // Auth check for all API routes
  if (pathname.startsWith('/api/')) {
    const storedAuth = getAuth();
    if (storedAuth && params.auth !== storedAuth) {
      return sendJSON(res, 403, { status: 'error', message: 'Invalid or missing auth key' });
    }
  }

  // Route dispatch
  if (pathname === '/api/trial-ssh')      return handleTrialSSH(params, res);
  if (pathname === '/api/create-ssh')     return handleCreateSSH(params, res);
  if (pathname === '/api/trial-vmess')    return handleTrialVmess(params, res);
  if (pathname === '/api/create-vmess')   return handleCreateVmess(params, res);
  if (pathname === '/api/trial-vless')    return handleTrialVless(params, res);
  if (pathname === '/api/create-vless')   return handleCreateVless(params, res);
  if (pathname === '/api/trial-trojan')   return handleTrialTrojan(params, res);
  if (pathname === '/api/create-trojan')  return handleCreateTrojan(params, res);

  // 404
  sendJSON(res, 404, { status: 'error', message: `Endpoint not found: ${pathname}. See /api/doc.html` });
});

server.listen(PORT, () => {
  console.log(`[ARISCTUNNEL API] Running on port ${PORT}`);
  console.log(`[ARISCTUNNEL API] Docs: http://localhost:${PORT}/api/doc.html`);
});
