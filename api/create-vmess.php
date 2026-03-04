<?php
header('Content-Type: application/json');
header('Access-Control-Allow-Origin: *');

$auth_file = '/etc/xray/api_auth.key';
$auth = $_GET['auth'] ?? '';
$user = preg_replace('/[^a-zA-Z0-9_]/', '', $_GET['user'] ?? '');
$quota = intval($_GET['quota'] ?? 0);
$iplimit = intval($_GET['limitip'] ?? 1);
$exp = intval($_GET['exp'] ?? 1);

if (!file_exists($auth_file) || trim(file_get_contents($auth_file)) !== $auth) {
    http_response_code(403);
    echo json_encode(['status' => 'error', 'message' => 'Invalid auth key']);
    exit;
}

if (empty($user)) {
    http_response_code(400);
    echo json_encode(['status' => 'error', 'message' => 'Parameter user diperlukan']);
    exit;
}

// Check existing
$existing = trim(shell_exec("grep -w $user /etc/xray/config.json | wc -l"));
if (intval($existing) > 0) {
    http_response_code(400);
    echo json_encode(['status' => 'error', 'message' => 'Username sudah ada']);
    exit;
}

$domain = trim(shell_exec('cat /etc/xray/domain 2>/dev/null'));
$uuid = trim(shell_exec('cat /proc/sys/kernel/random/uuid'));
$exp_date = date('Y-m-d', strtotime("+$exp days"));
$expe = date('d M, Y', strtotime("+$exp days"));
$created = date('d M, Y');

// Add to xray config
shell_exec("sed -i '/#vmess$/a\\### $user $exp_date\\\\n},{\"id\": \"$uuid\",\"alterId\": 0,\"email\": \"$user\"' /etc/xray/config.json");
shell_exec("sed -i '/#vmessgrpc$/a\\### $user $exp_date\\\\n},{\"id\": \"$uuid\",\"alterId\": 0,\"email\": \"$user\"' /etc/xray/config.json");
shell_exec("systemctl restart xray 2>/dev/null");

// Set IP limit
if ($iplimit > 0) {
    shell_exec("mkdir -p /etc/kyt/limit/vmess/ip");
    file_put_contents("/etc/kyt/limit/vmess/ip/$user", $iplimit);
}

// Set quota
if ($quota > 0) {
    $quota_bytes = $quota * 1024 * 1024 * 1024;
    shell_exec("mkdir -p /etc/vmess");
    file_put_contents("/etc/vmess/$user", $quota_bytes);
}

// Save to db
$db_line = "### $user $exp_date $uuid $quota $iplimit";
file_put_contents('/etc/vmess/.vmess.db', $db_line . "\n", FILE_APPEND);

// Build vmess links
$ws_tls_link = "vmess://" . base64_encode(json_encode([
    'v' => '2', 'ps' => "$user-TLS", 'add' => $domain,
    'port' => '443', 'id' => $uuid, 'aid' => '0',
    'net' => 'ws', 'path' => '/vmess', 'type' => 'none',
    'host' => $domain, 'tls' => 'tls'
]));

$ws_ntls_link = "vmess://" . base64_encode(json_encode([
    'v' => '2', 'ps' => "$user-NoneTLS", 'add' => $domain,
    'port' => '80', 'id' => $uuid, 'aid' => '0',
    'net' => 'ws', 'path' => '/vmess', 'type' => 'none',
    'host' => $domain, 'tls' => 'none'
]));

$grpc_link = "vmess://" . base64_encode(json_encode([
    'v' => '2', 'ps' => "$user-gRPC", 'add' => $domain,
    'port' => '443', 'id' => $uuid, 'aid' => '0',
    'net' => 'grpc', 'path' => 'vmess-grpc', 'type' => 'none',
    'host' => '', 'tls' => 'tls'
]));

// Save openclash config
$openclash_text = "- name: Vmess-$user-WS TLS
  type: vmess
  server: $domain
  port: 443
  uuid: $uuid
  alterId: 0
  cipher: auto
  tls: true
  skip-cert-verify: true
  network: ws
  ws-opts:
    path: /vmess
    headers:
      Host: $domain
- name: Vmess-$user-WS Non TLS
  type: vmess
  server: $domain
  port: 80
  uuid: $uuid
  alterId: 0
  cipher: auto
  tls: false
  network: ws
  ws-opts:
    path: /vmess
    headers:
      Host: $domain";

file_put_contents("/var/www/html/vmess-$user-$uuid.txt", $openclash_text);

$response = [
    'status' => 'success',
    'data' => [
        'user' => $user,
        'uuid' => $uuid,
        'expired' => "$exp Days ($expe)",
        'domain' => $domain,
        'ws_tls' => $ws_tls_link,
        'ws_none_tls' => $ws_ntls_link,
        'grpc' => $grpc_link,
        'openclash' => "https://$domain:81/vmess-$user-$uuid.txt",
        'dashboard_url' => "https://$domain/api/vmess-$user-$uuid.html",
        'quota' => $quota > 0 ? "$quota GB" : 'Unlimited',
        'limitip' => $iplimit
    ]
];

echo json_encode($response, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES);
