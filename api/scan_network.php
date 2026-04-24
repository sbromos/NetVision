<?php
// Risposta sempre in formato JSON
header('Content-Type: application/json');

require '../includes/db.php';
require '../includes/nmap_helper.php';

/**
 * Rileva la subnet IPv4 locale tramite ipconfig (Windows) o ip (Linux/Mac).
 */
function detectLocalSubnet(): string
{
    $output = [];

    if (PHP_OS_FAMILY === 'Windows') {
        exec('ipconfig', $output);
        foreach ($output as $line) {
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

/**
 * Tenta di indovinare il tipo di dispositivo a partire dal nome del produttore
 * della scheda di rete (OUI), estratto dall'output di nmap.
 * Restituisce 'unknown' se non riesce a classificarlo.
 */
function guessDeviceType(string $manufacturer): string
{
    $m = strtolower($manufacturer);

    // Router e access point
    if (preg_match('/cisco|juniper|mikrotik|ubiquiti|unifi|zyxel|draytek|fortinet|paloalto|edgewater/', $m)) {
        return 'router';
    }

    // Switch (spesso gli stessi vendor dei router, ma anche altri)
    if (preg_match('/netgear|d-link|dlink|tp-link|tplink|linksys|trendnet|buffalo|asus|huawei/', $m)) {
        return 'router';
    }

    // Stampanti
    if (preg_match('/hewlett|hp inc|canon|epson|brother|lexmark|xerox|ricoh|kyocera|sharp|konica|oki/', $m)) {
        return 'printer';
    }

    // Telecamere / NVR
    if (preg_match('/hikvision|dahua|axis|bosch|hanwha|vivotek|uniview|reolink|amcrest|foscam/', $m)) {
        return 'camera';
    }

    // Telefoni e dispositivi mobili
    if (preg_match('/samsung|xiaomi|oneplus|oppo|vivo|huawei|motorola|lg electron|sony mobile|nokia|zte/', $m)) {
        return 'phone';
    }

    // Apple: può essere phone, laptop o pc — usiamo 'laptop' come default ragionevole
    if (preg_match('/apple/', $m)) {
        return 'laptop';
    }

    // Server e NAS
    if (preg_match('/supermicro|dell|intel corp|synology|qnap|western digital|seagate|ibm/', $m)) {
        return 'server';
    }

    // PC generici (schede madri e adattatori comuni)
    if (preg_match('/realtek|intel|asustek|gigabyte|msi|asrock|acer|lenovo/', $m)) {
        return 'pc';
    }

    return 'unknown';
}

$nmap   = findNmapExecutable();
$subnet = detectLocalSubnet();

if ($nmap !== 'nmap' && !file_exists($nmap)) {
    echo json_encode([
        'error'   => true,
        'message' => 'Nmap non trovato. Installalo da https://nmap.org e riavvia Apache.',
    ]);
    exit();
}

// -sn = ping scan, -R = risoluzione DNS
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

// ── Parsing output nmap ──────────────────────────────────────────────────────
// Raccoglie: ip, hostname, produttore MAC per ogni host trovato
$foundIps       = [];
$foundHostnames = [];   // ip => hostname
$foundVendors   = [];   // ip => produttore scheda di rete

$currentIp = null;

foreach ($nmapOutput as $line) {
    // Riga "Nmap scan report for hostname (192.168.1.1)"
    if (preg_match('/Nmap scan report for (.+?) \((\d+\.\d+\.\d+\.\d+)\)/', $line, $m)) {
        $currentIp = $m[2];
        $foundIps[]               = $currentIp;
        $foundHostnames[$currentIp] = trim($m[1]);

    // Riga "Nmap scan report for 192.168.1.25" (senza hostname)
    } elseif (preg_match('/Nmap scan report for (\d+\.\d+\.\d+\.\d+)\s*$/', $line, $m)) {
        $currentIp = $m[1];
        $foundIps[] = $currentIp;

    // Riga "MAC Address: AA:BB:CC:DD:EE:FF (Vendor Name)"
    } elseif ($currentIp !== null && preg_match('/MAC Address:\s*[\dA-Fa-f:]+\s*\(([^)]+)\)/', $line, $m)) {
        $foundVendors[$currentIp] = trim($m[1]);
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
    $name         = $foundHostnames[$ip] ?? 'Dispositivo sconosciuto';
    $manufacturer = $foundVendors[$ip]   ?? '';
    $guessedType  = guessDeviceType($manufacturer);

    $check = $con->prepare("SELECT id, type FROM devices WHERE ip = ?");
    $check->bind_param("s", $ip);
    $check->execute();
    $checkResult = $check->get_result();

    if ($checkResult->num_rows > 0) {
        $existing = $checkResult->fetch_assoc();

        // Aggiorna status e timestamp; se il tipo era 'unknown' lo migliora col tipo dedotto
        if ($existing['type'] === 'unknown' && $guessedType !== 'unknown') {
            $upd = $con->prepare(
                "UPDATE devices SET status = 'online', last_check = NOW(), type = ? WHERE ip = ?"
            );
            $upd->bind_param("ss", $guessedType, $ip);
        } else {
            $upd = $con->prepare("UPDATE devices SET status = 'online', last_check = NOW() WHERE ip = ?");
            $upd->bind_param("s", $ip);
        }
        $upd->execute();

    } else {
        // Nuovo dispositivo: inserisce con tipo dedotto dal produttore
        $ins = $con->prepare(
            "INSERT INTO devices (name, ip, type, status, last_check)
             VALUES (?, ?, ?, 'online', NOW())"
        );
        $ins->bind_param("sss", $name, $ip, $guessedType);
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
