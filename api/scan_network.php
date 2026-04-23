<?php
session_start();

header('Content-Type: application/json');

if (!isset($_SESSION['logged_in'])) {
    http_response_code(401);
    echo json_encode([
        'success' => false,
        'message' => 'Sessione non valida.',
    ]);
    exit();
}

require '../includes/db.php';
require '../includes/network_helpers.php';

nvEnsureMonitoringTables($con);

$result = $con->query("SELECT * FROM devices ORDER BY name ASC");
$devices = $result ? $result->fetch_all(MYSQLI_ASSOC) : [];
$primarySubnet = nvGetPrimaryIpv4Subnet($devices);

if ($primarySubnet === null || empty($primarySubnet['base'])) {
    http_response_code(400);
    echo json_encode([
        'success' => false,
        'message' => 'Serve almeno un dispositivo IPv4 per dedurre la subnet principale.',
    ]);
    exit();
}

$existingByIp = [];
foreach ($devices as $device) {
    $existingByIp[$device['ip']] = $device;
}

$scanned = 0;
$responsive = 0;
$created = 0;
$updated = 0;

for ($host = 1; $host <= 254; $host++) {
    $ip = $primarySubnet['base'] . '.' . $host;
    $scanned++;

    $pingResult = nvPingAddress($ip, 180);
    if (!$pingResult['reachable']) {
        continue;
    }

    $responsive++;

    if (isset($existingByIp[$ip])) {
        $device = $existingByIp[$ip];
        $update = nvUpdateDeviceStatus(
            $con,
            $device,
            'online',
            'network-scan',
            $pingResult['response_time_ms']
        );

        $existingByIp[$ip]['status'] = 'online';
        $existingByIp[$ip]['last_check'] = $update['last_check'];
        $updated++;
        continue;
    }

    $hostName = nvResolveHostName($ip);
    $deviceId = nvCreateDiscoveredDevice($con, $ip, $hostName, 'network-scan');
    $created++;

    $existingByIp[$ip] = [
        'id' => $deviceId,
        'name' => nvGuessDeviceName($ip, $hostName),
        'ip' => $ip,
        'type' => nvGuessDeviceType($hostName),
        'status' => 'online',
        'last_check' => date('Y-m-d H:i:s'),
    ];
}

$refreshedResult = $con->query("SELECT * FROM devices ORDER BY name ASC");
$refreshedDevices = $refreshedResult ? $refreshedResult->fetch_all(MYSQLI_ASSOC) : [];

echo json_encode([
    'success' => true,
    'message' => sprintf(
        'Scansione completata: %d host attivi, %d nuovi dispositivi, %d aggiornati.',
        $responsive,
        $created,
        $updated
    ),
    'summary' => [
        'subnet' => $primarySubnet['network'],
        'scanned' => $scanned,
        'responsive' => $responsive,
        'created' => $created,
        'updated' => $updated,
    ],
    'dashboard' => nvBuildDashboardPayload($con, $refreshedDevices),
]);
