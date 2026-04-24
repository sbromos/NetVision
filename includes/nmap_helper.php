<?php
/**
 * Restituisce il percorso assoluto dell'eseguibile nmap.
 * Su Windows, Apache non eredita il PATH dell'utente, quindi cerchiamo
 * nelle directory di installazione standard prima di provare il solo nome.
 */
function findNmapExecutable(): string
{
    $windowsPaths = [
        'C:\\Program Files (x86)\\Nmap\\nmap.exe',
        'C:\\Program Files\\Nmap\\nmap.exe',
    ];

    foreach ($windowsPaths as $path) {
        if (file_exists($path)) {
            return $path;
        }
    }

    return 'nmap';
}

/**
 * Esegue "nmap --iflist" e restituisce le informazioni reali di rete
 * (interfaccia locale, subnet, maschera, gateway, broadcast, range host).
 *
 * Restituisce null se nmap non è disponibile o non trova interfacce valide.
 *
 * @param string $nmap Percorso dell'eseguibile nmap (da findNmapExecutable())
 * @return array{
 *   network: string,
 *   mask: string,
 *   cidr: string,
 *   gateway: string,
 *   host_range: string,
 *   broadcast: string,
 *   usable_hosts: int,
 *   network_type: string,
 *   local_ip: string
 * }|null
 */
function getRealNetworkInfo(string $nmap): ?array
{
    $output = [];
    exec(escapeshellarg($nmap) . ' --iflist', $output);

    $inInterfaces = false;
    $inRoutes     = false;

    // Mappa: short_name => ['ip' => ..., 'prefix' => ...]
    $interfaces = [];
    $defaultDev = null;
    $gateway    = null;

    foreach ($output as $rawLine) {
        $line = trim($rawLine);

        // Intestazioni sezioni
        if (strpos($line, 'INTERFACES') !== false) {
            $inInterfaces = true;
            $inRoutes     = false;
            continue;
        }
        if (strpos($line, 'ROUTES') !== false) {
            $inInterfaces = false;
            $inRoutes     = true;
            continue;
        }

        // Salta righe di intestazione colonne e separatori
        if (preg_match('/^DEV\s+/i', $line) || preg_match('/^\*+$/', $line) || $line === '') {
            continue;
        }

        // ── Sezione INTERFACES ──────────────────────────────────────────────
        // Formato: "DevName  (SHORT)  IP/MASK  TYPE  UP  MTU  MAC"
        if ($inInterfaces) {
            // Estrae il nome breve tra parentesi e l'IP/CIDR
            if (preg_match('/\(([^)]+)\).*?(\d+\.\d+\.\d+\.\d+)\/(\d+)/', $line, $m)) {
                $shortName = trim($m[1]);
                $ip        = $m[2];
                $prefix    = (int) $m[3];

                // Scarta loopback
                if (strpos($ip, '127.') === 0 || $prefix >= 32 || stripos($line, 'loopback') !== false) {
                    continue;
                }

                $interfaces[$shortName] = ['ip' => $ip, 'prefix' => $prefix];
            }
        }

        // ── Sezione ROUTES ──────────────────────────────────────────────────
        // Formato: "DST/MASK  DEV  METRIC  GATEWAY"
        if ($inRoutes && $defaultDev === null) {
            if (preg_match('/^0\.0\.0\.0\/0\s+(\S+)/', $line, $m)) {
                $defaultDev = $m[1];
                // Estrae il gateway (ultimo IP della riga)
                if (preg_match('/(\d+\.\d+\.\d+\.\d+)\s*$/', $line, $gm) && $gm[1] !== '0.0.0.0') {
                    $gateway = $gm[1];
                }
            }
        }
    }

    // Sceglie l'interfaccia: preferisce quella della rotta di default,
    // altrimenti la prima disponibile
    $interfaceData = null;
    if ($defaultDev !== null && isset($interfaces[$defaultDev])) {
        $interfaceData = $interfaces[$defaultDev];
    } elseif (!empty($interfaces)) {
        $interfaceData = reset($interfaces);
    }

    if ($interfaceData === null) {
        return null;
    }

    $ip     = $interfaceData['ip'];
    $prefix = $interfaceData['prefix'];

    // ── Calcolo parametri subnet ────────────────────────────────────────────
    $maskInt       = (-1 << (32 - $prefix)) & 0xFFFFFFFF;
    $ipLong        = ip2long($ip);
    $networkLong   = $ipLong & $maskInt;
    $broadcastLong = $networkLong | (~$maskInt & 0xFFFFFFFF);
    $usableHosts   = max(0, (int) pow(2, 32 - $prefix) - 2);

    $networkStr   = long2ip($networkLong);
    $maskStr      = long2ip($maskInt);
    $broadcastStr = long2ip($broadcastLong);
    $firstHost    = long2ip($networkLong + 1);
    $lastHost     = long2ip($broadcastLong - 1);

    // ── Tipo di rete (RFC1918) ──────────────────────────────────────────────
    $parts     = explode('.', $ip);
    $isPrivate = (
        $parts[0] === '10'
        || ($parts[0] === '172' && (int) $parts[1] >= 16 && (int) $parts[1] <= 31)
        || ($parts[0] === '192' && $parts[1] === '168')
    );

    return [
        'network'      => $networkStr,
        'mask'         => $maskStr,
        'cidr'         => '/' . $prefix,
        'gateway'      => $gateway ?? $firstHost,
        'host_range'   => $firstHost . ' - ' . $lastHost,
        'broadcast'    => $broadcastStr,
        'usable_hosts' => $usableHosts,
        'network_type' => $isPrivate ? 'Privata (RFC1918)' : 'Pubblica o personalizzata',
        'local_ip'     => $ip,
        // Valori grezzi utili per calcoli successivi (es. assigned_hosts)
        '_network_long' => $networkLong,
        '_mask_int'     => $maskInt,
    ];
}

/**
 * Conta quanti dispositivi del DB hanno un IP IPv4 che ricade nella subnet rilevata.
 *
 * @param array $devices Array di dispositivi dal DB (con chiave 'ip')
 * @param int $networkLong Indirizzo di rete come intero (da getRealNetworkInfo)
 * @param int $maskInt     Maschera come intero (da getRealNetworkInfo)
 */
function countDevicesInSubnet(array $devices, int $networkLong, int $maskInt): int
{
    $count = 0;
    foreach ($devices as $device) {
        $devIp = trim($device['ip'] ?? '');
        if (filter_var($devIp, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4) === false) {
            continue;
        }
        if ((ip2long($devIp) & $maskInt) === $networkLong) {
            $count++;
        }
    }
    return $count;
}
