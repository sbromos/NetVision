<?php
// Risposta sempre in formato JSON
header('Content-Type: application/json');

require '../includes/db.php';
require '../includes/nmap_helper.php';

/**
 * Rileva la subnet IPv4 locale tramite ipconfig (Windows) o ip (Linux/Mac).
 * Usata per determinare il range da passare a nmap per la scansione.
 */
function detectLocalSubnet(): string
{
    $output = [];

    if (PHP_OS_FAMILY === 'Windows') {
        exec('ipconfig', $output);
        foreach ($output as $line) {
            // Compatibile con Windows in italiano e inglese
            if (preg_match('/IPv4[^:]*:\s*([\d.]+)/i', $line, $m)) {
                $ip = trim($m[1]);
                if (
                    filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4) !== false
                    && strpos($ip, '127.') !== 0
                ) {
                    $parts = explode('.', $ip);
                    return $parts[0] . '.' . $parts[1] . '.' . $parts[2] . '.0/24';
                }
            }
        }
    } else {
        exec("ip -4 addr show scope global | grep inet", $output);
        foreach ($output as $line) {
            if (preg_match('/inet\s+([\d.]+)\/\d+/', $line, $m)) {
                $ip = $m[1];
                if (strpos($ip, '127.') !== 0) {
                    $parts = explode('.', $ip);
                    return $parts[0] . '.' . $parts[1] . '.' . $parts[2] . '.0/24';
                }
            }
        }
    }

    return '192.168.1.0/24';
}

$nmap   = findNmapExecutable();
$subnet = detectLocalSubnet();

// Verifica che l'eseguibile esista prima di lanciarlo
if ($nmap !== 'nmap' && !file_exists($nmap)) {
    echo json_encode([
        'error'   => true,
        'message' => 'Nmap non trovato. Installalo da https://nmap.org e riavvia Apache.',
    ]);
    exit();
}

// Esegue nmap: -sn = ping scan senza port scan, -R = risoluzione DNS per hostname
// escapeshellarg() e il path calcolato server-side proteggono da injection
$nmapOutput = [];
$returnCode = 0;
exec(escapeshellarg($nmap) . ' -sn -R ' . escapeshellarg($subnet), $nmapOutput, $returnCode);

if ($returnCode !== 0 && empty($nmapOutput)) {
    echo json_encode([
        'error'   => true,
        'message' => 'Nmap ha restituito un errore (codice ' . $returnCode . '). Prova ad eseguire Apache come amministratore.',
    ]);
    exit();
}

$foundIps       = [];
$foundHostnames = []; // mappa ip => hostname (se disponibile tramite DNS)

foreach ($nmapOutput as $line) {
    // Formato con hostname: "Nmap scan report for router.lan (192.168.1.1)"
    if (preg_match('/Nmap scan report for (.+?) \((\d+\.\d+\.\d+\.\d+)\)/', $line, $m)) {
        $ip       = $m[2];
        $hostname = trim($m[1]);
        $foundIps[]          = $ip;
        $foundHostnames[$ip] = $hostname;

    // Formato senza hostname: "Nmap scan report for 192.168.1.25"
    } elseif (preg_match('/Nmap scan report for (\d+\.\d+\.\d+\.\d+)\s*$/', $line, $m)) {
        $foundIps[] = $m[1];
    }
}

if (empty($foundIps)) {
    echo json_encode([
        'error'   => true,
        'message' => 'Nessun dispositivo rilevato nella subnet ' . $subnet . '. Verifica la connessione di rete o prova ad eseguire Apache come amministratore.',
    ]);
    exit();
}

$result = [];

// ── Aggiorna o inserisce ogni IP trovato ─────────────────────────────────────
foreach ($foundIps as $ip) {
    $name = $foundHostnames[$ip] ?? 'Dispositivo sconosciuto';

    $check = $con->prepare("SELECT id FROM devices WHERE ip = ?");
    $check->bind_param("s", $ip);
    $check->execute();
    $check->store_result();

    if ($check->num_rows > 0) {
        $upd = $con->prepare("UPDATE devices SET status = 'online', last_check = NOW() WHERE ip = ?");
        $upd->bind_param("s", $ip);
        $upd->execute();
    } else {
        $ins = $con->prepare(
            "INSERT INTO devices (name, ip, type, status, last_check)
             VALUES (?, ?, 'unknown', 'online', NOW())"
        );
        $ins->bind_param("ss", $name, $ip);
        $ins->execute();
    }

    $result[] = ['ip' => $ip, 'status' => 'online'];
}

// ── Imposta offline tutti i dispositivi NON rilevati dalla scansione ─────────
$placeholders = implode(',', array_fill(0, count($foundIps), '?'));
$types        = str_repeat('s', count($foundIps));

$offStmt = $con->prepare(
    "UPDATE devices SET status = 'offline'
     WHERE ip NOT IN ($placeholders)"
);
$offStmt->bind_param($types, ...$foundIps);
$offStmt->execute();

echo json_encode($result);
