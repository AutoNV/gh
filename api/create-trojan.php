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
shell_exec("sed -i '/#trojanws$/a\\#! $user $exp_date\\\\n},{\"password\": \"$uuid\",\"email\": \"$user\"' /etc/xray/config.json");
shell_exec("sed -i '/#trojangrpc$/a\\#! $user $exp_date\\\\n},{\"password\": \"$uuid\",\"email\": \"$user\"' /etc/xray/config.json");
shell_exec("systemctl restart xray 2>/dev/null");

if ($iplimit > 0) {
    shell_exec("mkdir -p /etc/kyt/limit/trojan/ip");
    file_put_contents("/etc/kyt/limit/trojan/ip/$user", $iplimit);
}

if ($quota > 0) {
    $quota_bytes = $quota * 1024 * 1024 * 1024;
    shell_exec("mkdir -p /etc/trojan");
    file_put_contents("/etc/trojan/$user", $quota_bytes);
}

$db_line = "#! $user $exp_date $uuid $quota $iplimit";
file_put_contents('/etc/trojan/.trojan.db', $db_line . "\n", FILE_APPEND);

$ws = "trojan://$uuid@$domain:443?path=%2Ftrojan-ws&security=tls&host=$domain&type=ws&sni=$domain#$user";
$grpc = "trojan://$uuid@$domain:443?mode=gun&security=tls&type=grpc&serviceName=trojan-grpc&sni=$domain#$user";

$openclash_text = "- name: Trojan-$user-WS
  server: $domain
  port: 443
  type: trojan
  password: $uuid
  network: ws
  sni: $domain
  skip-cert-verify: true
  ws-opts:
    path: /trojan-ws
    headers:
      Host: $domain
- name: Trojan-$user-gRPC
  server: $domain
  port: 443
  type: trojan
  password: $uuid
  sni: $domain
  skip-cert-verify: true
  network: grpc
  grpc-opts:
    grpc-service-name: trojan-grpc";

file_put_contents("/var/www/html/trojan-$user-$uuid.txt", $openclash_text);

$response = [
    'status' => 'success',
    'data' => [
        'user' => $user,
        'uuid' => $uuid,
        'expired' => "$exp Days ($expe)",
        'domain' => $domain,
        'ws' => $ws,
        'grpc' => $grpc,
        'openclash' => "https://$domain:81/trojan-$user-$uuid.txt",
        'dashboard_url' => "https://$domain/api/trojan-$user-$uuid.html",
        'quota' => $quota > 0 ? "$quota GB" : 'Unlimited',
        'limitip' => $iplimit
    ]
];

echo json_encode($response, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES);
