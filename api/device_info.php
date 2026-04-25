<?php
header('Content-Type: application/json');

require '../includes/db.php';
require '../includes/nmap_helper.php';

$id = isset($_GET['id']) ? (int) $_GET['id'] : 0;

if ($id <= 0) {
    echo json_encode(['error' => true, 'message' => 'ID dispositivo non valido.']);
    exit();
}

// Recupera l'IP dal DB (non si accetta mai l'IP direttamente dall'utente)
$stmt = $con->prepare("SELECT id, name, ip, type, status, ping_ms, notes FROM devices WHERE id = ?");
$stmt->bind_param("i", $id);
$stmt->execute();
$result = $stmt->get_result();

if ($result->num_rows === 0) {
    echo json_encode(['error' => true, 'message' => 'Dispositivo non trovato.']);
    exit();
}

$device = $result->fetch_assoc();
$ip     = trim($device['ip']);

// Accetta solo IPv4/IPv6 puri (no scoped)
if (filter_var($ip, FILTER_VALIDATE_IP) === false) {
    // Prova a rimuovere la parte scope (es. fe80::1%15 → fe80::1)
    $base = explode('%', $ip)[0];
    if (filter_var($base, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6) === false) {
        echo json_encode(['error' => true, 'message' => 'Indirizzo IP non supportato per la scansione porte.']);
        exit();
    }
    $ip = $base;
}

$nmap = findNmapExecutable();

if ($nmap !== 'nmap' && !file_exists($nmap)) {
    echo json_encode(['error' => true, 'message' => 'Nmap non trovato. Installalo da https://nmap.org e riavvia Apache.']);
    exit();
}

// Scansione veloce: porte più comuni, rilevamento servizi, timeout 15 secondi
$nmapOut    = [];
$returnCode = 0;
exec(
    escapeshellarg($nmap) . ' -sV -F --open --host-timeout 15s ' . escapeshellarg($ip),
    $nmapOut,
    $returnCode
);

// Parsing hostname
$hostname = null;
foreach ($nmapOut as $line) {
    if (preg_match('/Nmap scan report for (.+?) \(/', $line, $m)) {
        $hostname = trim($m[1]);
        break;
    }
}

// Parsing MAC address
$mac    = null;
$vendor = null;
foreach ($nmapOut as $line) {
    if (preg_match('/MAC Address:\s*([\dA-Fa-f:]{17})\s*\(([^)]+)\)/i', $line, $m)) {
        $mac    = strtoupper($m[1]);
        $vendor = trim($m[2]);
        break;
    }
}

// Parsing porte aperte: "80/tcp  open  http  Apache httpd 2.4"
$ports = [];
foreach ($nmapOut as $line) {
    $line = trim($line);
    if (preg_match('/^(\d+)\/(tcp|udp)\s+open\s+(\S+)\s*(.*)/i', $line, $m)) {
        $ports[] = [
            'port'    => (int) $m[1],
            'proto'   => strtoupper($m[2]),
            'service' => $m[3],
            'version' => trim($m[4]),
        ];
    }
}

echo json_encode([
    'error'    => false,
    'ip'       => $device['ip'],
    'name'     => $device['name'],
    'hostname' => $hostname,
    'mac'      => $mac,
    'vendor'   => $vendor,
    'ping_ms'  => $device['ping_ms'],
    'status'   => $device['status'],
    'ports'    => $ports,
]);
