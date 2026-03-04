<?php
header('Content-Type: application/json');
header('Access-Control-Allow-Origin: *');

$auth_file = '/etc/xray/api_auth.key';
$auth = $_GET['auth'] ?? '';
$user = $_GET['user'] ?? '';
$pass = $_GET['password'] ?? '';
$exp = intval($_GET['exp'] ?? 1);
$iplimit = intval($_GET['limitip'] ?? 1);

if (!file_exists($auth_file) || trim(file_get_contents($auth_file)) !== $auth) {
    http_response_code(403);
    echo json_encode(['status' => 'error', 'message' => 'Invalid auth key']);
    exit;
}

if (empty($user) || empty($pass)) {
    http_response_code(400);
    echo json_encode(['status' => 'error', 'message' => 'Parameter user dan password diperlukan']);
    exit;
}

// Sanitize username
$user = preg_replace('/[^a-zA-Z0-9_]/', '', $user);

// Check if user exists
$existing = trim(shell_exec("id $user 2>/dev/null"));
if (!empty($existing)) {
    http_response_code(400);
    echo json_encode(['status' => 'error', 'message' => 'Username sudah ada']);
    exit;
}

$domain = trim(shell_exec('cat /etc/xray/domain 2>/dev/null'));
$ip = trim(shell_exec('cat /usr/bin/ipsave 2>/dev/null'));
$isp = trim(shell_exec('cat /etc/xray/isp 2>/dev/null'));
$city = trim(shell_exec('cat /etc/xray/city 2>/dev/null'));

// Create SSH user
$exp_date = date('Y-m-d', strtotime("+$exp days"));
shell_exec("useradd -e $exp_date -s /bin/false -M $user 2>/dev/null");
shell_exec("printf '$pass\n$pass\n' | passwd $user 2>/dev/null");

// Set IP limit
if ($iplimit > 0) {
    shell_exec("mkdir -p /etc/kyt/limit/ssh/ip/");
    file_put_contents("/etc/kyt/limit/ssh/ip/$user", $iplimit);
}

// Expiry display
$expe = date('d M, Y', strtotime("+$exp days"));
$created = date('d M, Y');

// Save to db
$db_line = "#ssh# $user $pass 0 $iplimit $expe";
file_put_contents('/etc/ssh/.ssh.db', $db_line . "\n", FILE_APPEND);

// Create account file
$account_text = "======================
SSH OVPN Account
======================
Username         : $user
Password         : $pass
Expired          : $expe
======================
IP               : $ip
Host             : $domain
Port OpenSSH     : 443, 80, 22
Port Dropbear    : 443, 109
Port SSH UDP     : 1-65535
Port SSH WS      : 80, 8080, 8081-9999
Port SSH SSL WS  : 443
Port SSL/TLS     : 400-900
Port OVPN WS SSL : 443
Port OVPN SSL    : 443
Port OVPN TCP    : 1194
Port OVPN UDP    : 2200
BadVPN UDP       : 7100, 7300, 7300
======================";

file_put_contents("/var/www/html/ssh-$user.txt", $account_text);

$response = [
    'status' => 'success',
    'data' => [
        'username' => $user,
        'password' => $pass,
        'host' => $domain,
        'ip' => $ip,
        'ports' => [
            'openSSH' => '22',
            'dropbear' => '143, 109',
            'dropbearWS' => '443, 109',
            'sshUDP' => '1-65535',
            'ovpnWSSSL' => '443',
            'ovpnSSL' => '443',
            'ovpnTCP' => '1194',
            'ovpnUDP' => '2200',
            'badVPN' => '7100, 7300',
            'sshWS' => '80, 8080',
            'sshWSSSL' => '443'
        ],
        'formats' => [
            'port80' => "$domain:80@$user:$pass",
            'port443' => "$domain:443@$user:$pass",
            'udp' => "$domain:54-65535@$user:$pass"
        ],
        'ovpnDownload' => "https://$domain:81",
        'saveLink' => "https://$domain:81/ssh-$user.txt",
        'payloads' => [
            'wsNtls' => 'GET / HTTP/1.1[crlf]Host: [host][crlf]Connection: Upgrade[crlf]User-Agent: [ua][crlf]Upgrade: ws[crlf][crlf]',
            'wsTls' => 'GET / HTTP/1.1[crlf]Host: [host][crlf]Connection: Upgrade[crlf]User-Agent: [ua][crlf]Upgrade: ws[crlf][crlf]',
            'enhanced' => "PATCH / HTTP/1.1[crlf]Host: $domain[crlf]Host: bug.com[crlf]Upgrade: websocket[crlf]Connection: Upgrade[crlf][crlf]"
        ],
        'created' => $created,
        'expired' => "$exp Days ($expe)",
        'limitip' => $iplimit,
        'isp' => $isp,
        'city' => $city
    ]
];

echo json_encode($response, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES);
