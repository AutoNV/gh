<?php
header('Content-Type: application/json');
header('Access-Control-Allow-Origin: *');

$auth_file = '/etc/xray/api_auth.key';
$auth = $_GET['auth'] ?? '';

if (!file_exists($auth_file) || trim(file_get_contents($auth_file)) !== $auth) {
    http_response_code(403);
    echo json_encode(['status' => 'error', 'message' => 'Invalid auth key']);
    exit;
}

$domain = trim(shell_exec('cat /etc/xray/domain 2>/dev/null'));

// Generate trial user
$suffix = rand(1000, 9999);
$user = 'Trial' . $suffix;
$uuid = trim(shell_exec('cat /proc/sys/kernel/random/uuid'));
$exp_date = date('Y-m-d', strtotime('+60 minutes'));

// Add vmess user to xray config
shell_exec("sed -i '/#vmess$/a\\### $user $exp_date\\\\n},{\"id\": \"$uuid\",\"alterId\": 0,\"email\": \"$user\"' /etc/xray/config.json");
shell_exec("sed -i '/#vmessgrpc$/a\\### $user $exp_date\\\\n},{\"id\": \"$uuid\",\"alterId\": 0,\"email\": \"$user\"' /etc/xray/config.json");
shell_exec("systemctl restart xray 2>/dev/null");

// Remove after 60 min
shell_exec("echo \"sed -i '/\\\\b$user\\\\b/d' /etc/xray/config.json && systemctl restart xray\" | at now + 60 minutes 2>/dev/null");

// Build vmess links
$ws_tls_json = base64_encode(json_encode([
    'v' => '2', 'ps' => "$user-TLS", 'add' => $domain,
    'port' => '443', 'id' => $uuid, 'aid' => '0',
    'net' => 'ws', 'path' => '/vmess', 'type' => 'none',
    'host' => $domain, 'tls' => 'tls'
]));

$ws_ntls_json = base64_encode(json_encode([
    'v' => '2', 'ps' => "$user-NoneTLS", 'add' => $domain,
    'port' => '80', 'id' => $uuid, 'aid' => '0',
    'net' => 'ws', 'path' => '/vmess', 'type' => 'none',
    'host' => $domain, 'tls' => 'none'
]));

$grpc_json = base64_encode(json_encode([
    'v' => '2', 'ps' => "$user-gRPC", 'add' => $domain,
    'port' => '443', 'id' => $uuid, 'aid' => '0',
    'net' => 'grpc', 'path' => 'vmess-grpc', 'type' => 'none',
    'host' => '', 'tls' => 'tls'
]));

$ws_tls_link = "vmess://$ws_tls_json";
$ws_ntls_link = "vmess://$ws_ntls_json";
$grpc_link = "vmess://$grpc_json";

// Save openclash config
$openclash_text = "# $user Trial Vmess
- name: Vmess-$user-WS-TLS
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
      Host: $domain";

file_put_contents("/var/www/html/vmess-$user-$uuid.txt", $openclash_text);

$response = [
    'status' => 'success',
    'data' => [
        'user' => $user,
        'uuid' => $uuid,
        'expired' => '60 minutes',
        'domain' => $domain,
        'ws_tls' => $ws_tls_link,
        'ws_none_tls' => $ws_ntls_link,
        'grpc' => $grpc_link,
        'openclash' => "https://$domain:81/vmess-$user-$uuid.txt",
        'dashboard_url' => "https://$domain/api/vmess-$user-$uuid.html"
    ]
];

echo json_encode($response, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES);
