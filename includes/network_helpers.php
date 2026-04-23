<?php

function nvGetScopedIpv6Base(string $address): ?string
{
    if (substr_count($address, '%') !== 1) {
        return null;
    }

    [$baseIp, $scopeId] = explode('%', $address, 2);
    if ($baseIp === '' || $scopeId === '') {
        return null;
    }

    if (!preg_match('/^[A-Za-z0-9_.-]+$/', $scopeId)) {
        return null;
    }

    return $baseIp;
}

function nvIsValidIpAddress(string $address): bool
{
    if (filter_var($address, FILTER_VALIDATE_IP) !== false) {
        return true;
    }

    $baseIp = nvGetScopedIpv6Base($address);
    if ($baseIp === null) {
        return false;
    }

    return filter_var($baseIp, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6) !== false;
}

function nvIsIpv4Address(string $address): bool
{
    return filter_var($address, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4) !== false;
}

function nvIsPrivateIpv4Address(string $address): bool
{
    if (!nvIsIpv4Address($address)) {
        return false;
    }

    $parts = array_map('intval', explode('.', $address));

    if ($parts[0] === 10) {
        return true;
    }

    if ($parts[0] === 172 && $parts[1] >= 16 && $parts[1] <= 31) {
        return true;
    }

    return $parts[0] === 192 && $parts[1] === 168;
}

function nvGetPrimaryIpv4Subnet(array $devices): ?array
{
    $subnets = [];

    foreach ($devices as $device) {
        $ip = trim($device['ip'] ?? '');
        if (!nvIsIpv4Address($ip)) {
            continue;
        }

        $parts = explode('.', $ip);
        $base = $parts[0] . '.' . $parts[1] . '.' . $parts[2];

        if (!isset($subnets[$base])) {
            $subnets[$base] = [
                'network'        => $base . '.0',
                'mask'           => '255.255.255.0',
                'cidr'           => '/24',
                'gateway'        => $base . '.1',
                'host_range'     => $base . '.1 - ' . $base . '.254',
                'broadcast'      => $base . '.255',
                'usable_hosts'   => 254,
                'assigned_hosts' => 0,
                'network_type'   => nvIsPrivateIpv4Address($ip) ? 'Privata (RFC1918)' : 'Pubblica o personalizzata',
                'base'           => $base,
            ];
        }

        $subnets[$base]['assigned_hosts']++;
    }

    if ($subnets === []) {
        return null;
    }

    uasort($subnets, static function (array $left, array $right): int {
        return $right['assigned_hosts'] <=> $left['assigned_hosts'];
    });

    return reset($subnets) ?: null;
}

function nvGetIpPingFlag(string $address): ?string
{
    if (filter_var($address, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
        return '-4';
    }

    if (filter_var($address, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6)) {
        return '-6';
    }

    $baseIp = nvGetScopedIpv6Base($address);
    if ($baseIp !== null && filter_var($baseIp, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6)) {
        return '-6';
    }

    return null;
}

function nvEnsureMonitoringTables(mysqli $con): void
{
    $con->query("CREATE TABLE IF NOT EXISTS devices (
        id INT AUTO_INCREMENT PRIMARY KEY,
        name VARCHAR(100) NOT NULL,
        ip VARCHAR(45) NOT NULL,
        type VARCHAR(50) NOT NULL DEFAULT 'pc',
        status ENUM('online','offline','unknown') NOT NULL DEFAULT 'unknown',
        last_check DATETIME DEFAULT NULL
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4");

    $con->query("CREATE TABLE IF NOT EXISTS device_status_history (
        id INT AUTO_INCREMENT PRIMARY KEY,
        device_id INT NOT NULL,
        previous_status ENUM('online','offline','unknown') DEFAULT NULL,
        current_status ENUM('online','offline','unknown') NOT NULL,
        changed TINYINT(1) NOT NULL DEFAULT 0,
        source VARCHAR(50) NOT NULL DEFAULT 'manual-check',
        response_time_ms INT DEFAULT NULL,
        checked_at DATETIME NOT NULL,
        INDEX idx_device_checked_at (device_id, checked_at),
        CONSTRAINT fk_device_status_history_device
            FOREIGN KEY (device_id) REFERENCES devices(id) ON DELETE CASCADE
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4");

    $con->query("CREATE TABLE IF NOT EXISTS device_alerts (
        id INT AUTO_INCREMENT PRIMARY KEY,
        device_id INT DEFAULT NULL,
        category VARCHAR(50) NOT NULL,
        title VARCHAR(150) NOT NULL,
        message TEXT NOT NULL,
        created_at DATETIME NOT NULL,
        INDEX idx_alerts_created_at (created_at),
        CONSTRAINT fk_device_alerts_device
            FOREIGN KEY (device_id) REFERENCES devices(id) ON DELETE CASCADE
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4");
}

function nvCreateAlert(mysqli $con, ?int $deviceId, string $category, string $title, string $message): void
{
    $createdAt = date('Y-m-d H:i:s');
    $stmt = $con->prepare(
        "INSERT INTO device_alerts (device_id, category, title, message, created_at)
         VALUES (?, ?, ?, ?, ?)"
    );
    $stmt->bind_param('issss', $deviceId, $category, $title, $message, $createdAt);
    $stmt->execute();
    $stmt->close();
}

function nvGuessDeviceType(?string $hostName): string
{
    $name = strtolower((string) $hostName);
    if ($name === '') {
        return 'pc';
    }

    if (preg_match('/router|gateway|modem|ap-|accesspoint|mikrotik|ubiquiti|tplink|tp-link/', $name)) {
        return 'router';
    }

    if (preg_match('/switch/', $name)) {
        return 'switch';
    }

    if (preg_match('/print|printer|hp-|epson|canon/', $name)) {
        return 'printer';
    }

    if (preg_match('/cam|camera|cctv|hikvision|dahua/', $name)) {
        return 'camera';
    }

    if (preg_match('/iphone|android|phone|samsung|xiaomi|pixel/', $name)) {
        return 'phone';
    }

    if (preg_match('/server|srv|nas|synology|proxmox|esxi/', $name)) {
        return 'server';
    }

    if (preg_match('/laptop|notebook/', $name)) {
        return 'laptop';
    }

    return 'pc';
}

function nvGuessDeviceName(string $ip, ?string $hostName = null): string
{
    if ($hostName !== null && $hostName !== '' && $hostName !== $ip) {
        return $hostName;
    }

    return 'Host ' . $ip;
}

function nvResolveHostName(string $ip): ?string
{
    $hostName = @gethostbyaddr($ip);
    if ($hostName === false || $hostName === $ip) {
        return null;
    }

    return $hostName;
}

function nvPingAddress(string $address, int $timeoutMs = 500): array
{
    $flag = nvGetIpPingFlag($address);
    if ($flag === null) {
        return [
            'status' => 'offline',
            'reachable' => false,
            'response_time_ms' => null,
        ];
    }

    $timeoutMs = max(50, $timeoutMs);
    $output = [];
    $returnCode = 1;
    $startedAt = microtime(true);

    exec("ping {$flag} -n 1 -w {$timeoutMs} " . escapeshellarg($address), $output, $returnCode);

    return [
        'status' => $returnCode === 0 ? 'online' : 'offline',
        'reachable' => $returnCode === 0,
        'response_time_ms' => (int) round((microtime(true) - $startedAt) * 1000),
    ];
}

function nvUpdateDeviceStatus(mysqli $con, array $device, string $status, string $source, ?int $responseTimeMs = null): array
{
    $previousStatus = $device['status'] ?? 'unknown';
    $statusChanged = $previousStatus !== $status;
    $checkedAt = date('Y-m-d H:i:s');

    $stmt = $con->prepare("UPDATE devices SET status = ?, last_check = ? WHERE id = ?");
    $stmt->bind_param('ssi', $status, $checkedAt, $device['id']);
    $stmt->execute();
    $stmt->close();

    $historyStmt = $con->prepare(
        "INSERT INTO device_status_history
            (device_id, previous_status, current_status, changed, source, response_time_ms, checked_at)
         VALUES (?, ?, ?, ?, ?, ?, ?)"
    );
    $changedInt = $statusChanged ? 1 : 0;
    $historyStmt->bind_param(
        'issisis',
        $device['id'],
        $previousStatus,
        $status,
        $changedInt,
        $source,
        $responseTimeMs,
        $checkedAt
    );
    $historyStmt->execute();
    $historyStmt->close();

    if ($statusChanged && in_array($previousStatus, ['online', 'offline'], true)) {
        if ($status === 'offline') {
            nvCreateAlert(
                $con,
                (int) $device['id'],
                'device_offline',
                'Dispositivo offline',
                sprintf('%s non risponde piu\' al ping (%s).', $device['name'], $device['ip'])
            );
        } elseif ($status === 'online' && $previousStatus === 'offline') {
            nvCreateAlert(
                $con,
                (int) $device['id'],
                'device_online',
                'Dispositivo tornato online',
                sprintf('%s e\' di nuovo raggiungibile su %s.', $device['name'], $device['ip'])
            );
        }
    }

    return [
        'status' => $status,
        'last_check' => $checkedAt,
        'status_changed' => $statusChanged,
    ];
}

function nvCreateDiscoveredDevice(mysqli $con, string $ip, ?string $hostName, string $source = 'network-scan'): int
{
    $name = nvGuessDeviceName($ip, $hostName);
    $type = nvGuessDeviceType($hostName);
    $status = 'online';
    $checkedAt = date('Y-m-d H:i:s');

    $stmt = $con->prepare(
        "INSERT INTO devices (name, ip, type, status, last_check)
         VALUES (?, ?, ?, ?, ?)"
    );
    $stmt->bind_param('sssss', $name, $ip, $type, $status, $checkedAt);
    $stmt->execute();
    $deviceId = (int) $stmt->insert_id;
    $stmt->close();

    $historyStmt = $con->prepare(
        "INSERT INTO device_status_history
            (device_id, previous_status, current_status, changed, source, response_time_ms, checked_at)
         VALUES (?, ?, ?, ?, ?, ?, ?)"
    );
    $previousStatus = 'unknown';
    $changedInt = 1;
    $responseTimeMs = null;
    $historyStmt->bind_param(
        'issisis',
        $deviceId,
        $previousStatus,
        $status,
        $changedInt,
        $source,
        $responseTimeMs,
        $checkedAt
    );
    $historyStmt->execute();
    $historyStmt->close();

    nvCreateAlert(
        $con,
        $deviceId,
        'new_device',
        'Nuovo dispositivo rilevato',
        sprintf('%s e\' stato rilevato automaticamente su %s.', $name, $ip)
    );

    return $deviceId;
}

function nvFetchRecentAlerts(mysqli $con, int $limit = 6): array
{
    $limit = max(1, (int) $limit);
    $query = "SELECT a.*, d.name AS device_name, d.ip AS device_ip
              FROM device_alerts a
              LEFT JOIN devices d ON d.id = a.device_id
              ORDER BY a.created_at DESC
              LIMIT {$limit}";
    $result = $con->query($query);

    return $result ? $result->fetch_all(MYSQLI_ASSOC) : [];
}

function nvFetchRecentHistory(mysqli $con, int $limit = 8): array
{
    $limit = max(1, (int) $limit);
    $query = "SELECT h.*, d.name AS device_name, d.ip AS device_ip
              FROM device_status_history h
              INNER JOIN devices d ON d.id = h.device_id
              ORDER BY h.checked_at DESC, h.id DESC
              LIMIT {$limit}";
    $result = $con->query($query);

    return $result ? $result->fetch_all(MYSQLI_ASSOC) : [];
}

function nvFormatDateTime(?string $value): string
{
    if ($value === null || $value === '') {
        return 'Mai';
    }

    $timestamp = strtotime($value);
    if ($timestamp === false) {
        return $value;
    }

    return date('d/m/Y H:i', $timestamp);
}

function nvPrepareAlertsForView(array $alerts): array
{
    return array_map(static function (array $alert): array {
        $alert['created_at_label'] = nvFormatDateTime($alert['created_at'] ?? null);
        return $alert;
    }, $alerts);
}

function nvPrepareHistoryForView(array $history): array
{
    return array_map(static function (array $item): array {
        $item['checked_at_label'] = nvFormatDateTime($item['checked_at'] ?? null);
        return $item;
    }, $history);
}

function nvBuildDashboardMetrics(array $devices): array
{
    $onlineDevices = 0;
    $offlineDevices = 0;
    $unknownDevices = 0;
    $ipv4Count = 0;
    $typeCounts = [];

    foreach ($devices as $device) {
        $status = $device['status'] ?? 'unknown';
        if ($status === 'online') {
            $onlineDevices++;
        } elseif ($status === 'offline') {
            $offlineDevices++;
        } else {
            $unknownDevices++;
        }

        $ip = trim($device['ip'] ?? '');
        if (nvIsIpv4Address($ip)) {
            $ipv4Count++;
        }

        $type = $device['type'] ?? 'pc';
        if (!isset($typeCounts[$type])) {
            $typeCounts[$type] = 0;
        }
        $typeCounts[$type]++;
    }

    arsort($typeCounts);

    return [
        'total' => count($devices),
        'online' => $onlineDevices,
        'offline' => $offlineDevices,
        'unknown' => $unknownDevices,
        'ipv4' => $ipv4Count,
        'type_counts' => $typeCounts,
    ];
}

function nvBuildDashboardPayload(mysqli $con, array $devices): array
{
    $metrics = nvBuildDashboardMetrics($devices);
    $primarySubnet = nvGetPrimaryIpv4Subnet($devices);

    return [
        'metrics' => $metrics,
        'primary_subnet' => $primarySubnet,
        'alerts' => nvPrepareAlertsForView(nvFetchRecentAlerts($con)),
        'history' => nvPrepareHistoryForView(nvFetchRecentHistory($con)),
    ];
}
