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
shell_exec("sed -i '/#vless$/a\\#& $user $exp_date\\\\n},{\"id\": \"$uuid\",\"email\": \"$user\"' /etc/xray/config.json");
shell_exec("sed -i '/#vlessgrpc$/a\\#& $user $exp_date\\\\n},{\"id\": \"$uuid\",\"email\": \"$user\"' /etc/xray/config.json");
shell_exec("systemctl restart xray 2>/dev/null");

if ($iplimit > 0) {
    shell_exec("mkdir -p /etc/kyt/limit/vless/ip");
    file_put_contents("/etc/kyt/limit/vless/ip/$user", $iplimit);
}

if ($quota > 0) {
    $quota_bytes = $quota * 1024 * 1024 * 1024;
    shell_exec("mkdir -p /etc/vless");
    file_put_contents("/etc/vless/$user", $quota_bytes);
}

$db_line = "#& $user $exp_date $uuid $quota $iplimit";
file_put_contents('/etc/vless/.vless.db', $db_line . "\n", FILE_APPEND);

$ws_tls = "vless://$uuid@$domain:443?path=%2Fvless&security=tls&encryption=none&type=ws#$user-TLS";
$ws_ntls = "vless://$uuid@$domain:80?path=%2Fvless&encryption=none&type=ws#$user-NoneTLS";
$grpc = "vless://$uuid@$domain:443?mode=gun&security=tls&encryption=none&type=grpc&serviceName=vless-grpc&sni=$domain#$user-gRPC";

$openclash_text = "- name: Vless-$user-WS TLS
  server: $domain
  port: 443
  type: vless
  uuid: $uuid
  tls: true
  skip-cert-verify: true
  network: ws
  ws-opts:
    path: /vless
    headers:
      Host: $domain";

file_put_contents("/var/www/html/vless-$user-$uuid.txt", $openclash_text);

$response = [
    'status' => 'success',
    'data' => [
        'user' => $user,
        'uuid' => $uuid,
        'expired' => "$exp Days ($expe)",
        'domain' => $domain,
        'ws_tls' => $ws_tls,
        'ws_none_tls' => $ws_ntls,
        'grpc' => $grpc,
        'openclash' => "https://$domain:81/vless-$user-$uuid.txt",
        'dashboard_url' => "https://$domain/api/vless-$user-$uuid.html",
        'quota' => $quota > 0 ? "$quota GB" : 'Unlimited',
        'limitip' => $iplimit
    ]
];

echo json_encode($response, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES);
