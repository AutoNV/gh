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

// Add trojan to xray config
shell_exec("sed -i '/#trojanws$/a\\#! $user $exp_date\\\\n},{\"password\": \"$uuid\",\"email\": \"$user\"' /etc/xray/config.json");
shell_exec("sed -i '/#trojangrpc$/a\\#! $user $exp_date\\\\n},{\"password\": \"$uuid\",\"email\": \"$user\"' /etc/xray/config.json");
shell_exec("systemctl restart xray 2>/dev/null");

// Remove after 60 min
shell_exec("echo \"sed -i '/\\\\b$user\\\\b/d' /etc/xray/config.json && systemctl restart xray\" | at now + 60 minutes 2>/dev/null");

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
      Host: $domain";

file_put_contents("/var/www/html/trojan-$user-$uuid.txt", $openclash_text);

$response = [
    'status' => 'success',
    'data' => [
        'user' => $user,
        'uuid' => $uuid,
        'expired' => '60 minutes',
        'domain' => $domain,
        'ws' => $ws,
        'grpc' => $grpc,
        'openclash' => "https://$domain:81/trojan-$user-$uuid.txt",
        'dashboard_url' => "https://$domain/api/trojan-$user-$uuid.html"
    ]
];

echo json_encode($response, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES);
