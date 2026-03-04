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
$ip = trim(shell_exec('cat /usr/bin/ipsave 2>/dev/null'));
$isp = trim(shell_exec('cat /etc/xray/isp 2>/dev/null'));
$city = trim(shell_exec('cat /etc/xray/city 2>/dev/null'));

// Generate trial username
$suffix = strtoupper(substr(str_shuffle('ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789'), 0, 5));
$user = 'Trial' . $suffix;
$pass = '1';
$iplimit = 99;

// Create SSH user
shell_exec("useradd -e \$(date -d '60 minutes' +\"%Y-%m-%d\") -s /bin/false -M $user 2>/dev/null");
shell_exec("echo '$pass\n$pass\n' | passwd $user 2>/dev/null");

// Set expiry via at job
shell_exec("echo 'userdel $user' | at now + 60 minutes 2>/dev/null");

// Save to db
$db_line = "#ssh# $user $pass 0 $iplimit 60min";
file_put_contents('/etc/ssh/.ssh.db', $db_line . "\n", FILE_APPEND);

// Create account file
$account_text = "======================
Format SSH OVPN Account Trial
======================
Username         : $user
Password         : $pass
Berakhir Pada    : 60 Menit
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

$created = date('M d, Y');

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
        'expired' => '60 Minutes',
        'isp' => $isp,
        'city' => $city
    ]
];

echo json_encode($response, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES);
