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
if (!$result) {
    echo json_encode([
        'success' => true,
        'devices' => [],
        'dashboard' => nvBuildDashboardPayload($con, []),
    ]);
    exit();
}

$devices = $result->fetch_all(MYSQLI_ASSOC);
$output = [];

foreach ($devices as &$device) {
    $pingResult = nvPingAddress($device['ip']);
    $update = nvUpdateDeviceStatus(
        $con,
        $device,
        $pingResult['status'],
        'manual-check',
        $pingResult['response_time_ms']
    );

    $device['status'] = $update['status'];
    $device['last_check'] = $update['last_check'];

    $output[] = [
        'id' => (int) $device['id'],
        'status' => $device['status'],
        'last_check' => nvFormatDateTime($device['last_check']),
        'status_changed' => $update['status_changed'],
    ];
}
unset($device);

echo json_encode([
    'success' => true,
    'devices' => $output,
    'dashboard' => nvBuildDashboardPayload($con, $devices),
]);
