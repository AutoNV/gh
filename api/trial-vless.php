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

$suffix = rand(1000, 9999);
$user = 'Trial' . $suffix;
$uuid = trim(shell_exec('cat /proc/sys/kernel/random/uuid'));
$exp_date = date('Y-m-d', strtotime('+60 minutes'));

// Add vless to xray config
shell_exec("sed -i '/#vless$/a\\#& $user $exp_date\\\\n},{\"id\": \"$uuid\",\"email\": \"$user\"' /etc/xray/config.json");
shell_exec("sed -i '/#vlessgrpc$/a\\#& $user $exp_date\\\\n},{\"id\": \"$uuid\",\"email\": \"$user\"' /etc/xray/config.json");
shell_exec("systemctl restart xray 2>/dev/null");

// Remove after 60 min
shell_exec("echo \"sed -i '/\\\\b$user\\\\b/d' /etc/xray/config.json && systemctl restart xray\" | at now + 60 minutes 2>/dev/null");

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
        'expired' => '60 minutes',
        'domain' => $domain,
        'ws_tls' => $ws_tls,
        'ws_none_tls' => $ws_ntls,
        'grpc' => $grpc,
        'openclash' => "https://$domain:81/vless-$user-$uuid.txt",
        'dashboard_url' => "https://$domain/api/vless-$user-$uuid.html"
    ]
];

echo json_encode($response, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES);
