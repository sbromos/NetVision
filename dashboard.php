<?php
session_start();

if (!isset($_SESSION['logged_in'])) {
    header('Location: login.php');
    exit();
}

require 'includes/db.php';
require 'includes/network_helpers.php';

nvEnsureMonitoringTables($con);

$deviceError = $_SESSION['device_error'] ?? null;
unset($_SESSION['device_error']);

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $action = $_POST['action'] ?? '';

    if ($action === 'add') {
        $name = trim($_POST['name'] ?? '');
        $ipDev = trim($_POST['ip'] ?? '');
        $type = $_POST['type'] ?? 'pc';

        if ($name === '' || !nvIsValidIpAddress($ipDev)) {
            $_SESSION['device_error'] = 'Inserisci un nome e un indirizzo IP valido IPv4 o IPv6.';
        } else {
            $stmt = $con->prepare("INSERT INTO devices (name, ip, type) VALUES (?, ?, ?)");
            $stmt->bind_param('sss', $name, $ipDev, $type);
            $stmt->execute();
            $stmt->close();
        }
    } elseif ($action === 'edit') {
        $id = (int) ($_POST['id'] ?? 0);
        $name = trim($_POST['name'] ?? '');
        $ipDev = trim($_POST['ip'] ?? '');
        $type = $_POST['type'] ?? 'pc';

        if ($id <= 0 || $name === '' || !nvIsValidIpAddress($ipDev)) {
            $_SESSION['device_error'] = 'Inserisci un nome e un indirizzo IP valido IPv4 o IPv6.';
        } else {
            $stmt = $con->prepare("UPDATE devices SET name = ?, ip = ?, type = ? WHERE id = ?");
            $stmt->bind_param('sssi', $name, $ipDev, $type, $id);
            $stmt->execute();
            $stmt->close();
        }
    } elseif ($action === 'delete') {
        $id = (int) ($_POST['id'] ?? 0);
        if ($id > 0) {
            $stmt = $con->prepare("DELETE FROM devices WHERE id = ?");
            $stmt->bind_param('i', $id);
            $stmt->execute();
            $stmt->close();
        }
    }

    header('Location: dashboard.php');
    exit();
}

$result = $con->query("SELECT * FROM devices ORDER BY name ASC");
$devices = $result ? $result->fetch_all(MYSQLI_ASSOC) : [];

$dashboardData = nvBuildDashboardPayload($con, $devices);
$metrics = $dashboardData['metrics'];
$primarySubnet = $dashboardData['primary_subnet'];
$recentAlerts = $dashboardData['alerts'];
$recentHistory = $dashboardData['history'];
$scanAvailable = $primarySubnet !== null;
$topTypeCounts = array_slice($metrics['type_counts'], 0, 5, true);

$typeIcons = [
    'pc' => 'fa-desktop',
    'laptop' => 'fa-laptop',
    'server' => 'fa-server',
    'router' => 'fa-wifi',
    'switch' => 'fa-network-wired',
    'printer' => 'fa-print',
    'phone' => 'fa-mobile-alt',
    'camera' => 'fa-camera',
];

$typeLabels = [
    'pc' => 'PC',
    'laptop' => 'Laptop',
    'server' => 'Server',
    'router' => 'Router',
    'switch' => 'Switch',
    'printer' => 'Stampante',
    'phone' => 'Telefono',
    'camera' => 'Telecamera',
];

function renderAlertIcon(string $category): string
{
    if ($category === 'device_offline') {
        return 'fa-triangle-exclamation';
    }

    if ($category === 'device_online') {
        return 'fa-circle-check';
    }

    return 'fa-satellite-dish';
}
?>
<!DOCTYPE html>
<html lang="it">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>NetVision - Dashboard</title>
    <link rel="stylesheet" href="assets/css/dashboard.css">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.0/css/all.min.css">
</head>
<body>
<header class="topbar">
    <div class="topbar-left">
        <span class="topbar-logo">NetVision</span>
    </div>
    <div class="topbar-right">
        <span class="topbar-user"><i class="fas fa-user"></i> <?php echo htmlspecialchars($_SESSION['username']); ?></span>
        <a href="login.php" class="btn-logout"><i class="fas fa-sign-out-alt"></i> Esci</a>
    </div>
</header>

<main class="main-content">
    <div class="dashboard-layout">
        <aside class="network-sidebar">
            <div class="network-panel">
                <div class="network-panel-header">
                    <span class="panel-kicker">Panoramica</span>
                    <h2>Informazioni di rete</h2>
                    <p>Un riepilogo rapido della rete e dello stato dei dispositivi.</p>
                </div>

                <div class="network-stat-grid">
                    <div class="network-stat-card">
                        <span class="network-stat-label">Dispositivi</span>
                        <strong id="metricTotal"><?php echo $metrics['total']; ?></strong>
                    </div>
                    <div class="network-stat-card">
                        <span class="network-stat-label">Host usati</span>
                        <strong id="metricHostsUsed">
                            <?php
                            echo $primarySubnet
                                ? $primarySubnet['assigned_hosts'] . '/' . $primarySubnet['usable_hosts']
                                : '0/0';
                            ?>
                        </strong>
                    </div>
                    <div class="network-stat-card">
                        <span class="network-stat-label">Online</span>
                        <strong id="metricOnline"><?php echo $metrics['online']; ?></strong>
                    </div>
                    <div class="network-stat-card">
                        <span class="network-stat-label">Offline</span>
                        <strong id="metricOffline"><?php echo $metrics['offline']; ?></strong>
                    </div>
                </div>

                <div class="network-details">
                    <div class="network-detail-row">
                        <span>Pool IP principale</span>
                        <strong id="detailNetwork"><?php echo htmlspecialchars($primarySubnet['network'] ?? 'Non disponibile'); ?></strong>
                    </div>
                    <div class="network-detail-row">
                        <span>Maschera</span>
                        <strong id="detailMask">
                            <?php
                            echo $primarySubnet
                                ? htmlspecialchars($primarySubnet['mask'] . ' ' . $primarySubnet['cidr'])
                                : 'Non disponibile';
                            ?>
                        </strong>
                    </div>
                    <div class="network-detail-row">
                        <span>Range host</span>
                        <strong id="detailRange"><?php echo htmlspecialchars($primarySubnet['host_range'] ?? 'Non disponibile'); ?></strong>
                    </div>
                    <div class="network-detail-row">
                        <span>Broadcast</span>
                        <strong id="detailBroadcast"><?php echo htmlspecialchars($primarySubnet['broadcast'] ?? 'Non disponibile'); ?></strong>
                    </div>
                    <div class="network-detail-row">
                        <span>Gateway suggerito</span>
                        <strong id="detailGateway"><?php echo htmlspecialchars($primarySubnet['gateway'] ?? 'Non disponibile'); ?></strong>
                    </div>
                    <div class="network-detail-row">
                        <span>Tipo rete</span>
                        <strong id="detailType"><?php echo htmlspecialchars($primarySubnet['network_type'] ?? 'Non disponibile'); ?></strong>
                    </div>
                </div>

                <div class="network-note" id="networkNote">
                    <?php if ($primarySubnet): ?>
                    <p>
                        Subnet principale rilevata da <?php echo $primarySubnet['assigned_hosts']; ?>
                        dispositiv<?php echo $primarySubnet['assigned_hosts'] === 1 ? 'o' : 'i'; ?>
                        IPv4 su <?php echo $primarySubnet['usable_hosts']; ?> host disponibili.
                    </p>
                    <?php else: ?>
                    <p>Aggiungi almeno un dispositivo con IPv4 per visualizzare pool, maschera e range host della rete.</p>
                    <?php endif; ?>
                </div>
            </div>

            <div class="network-panel network-panel-secondary">
                <div class="network-panel-header">
                    <span class="panel-kicker">Alert interni</span>
                    <h2>Notifiche recenti</h2>
                    <p>Nuovi host rilevati, dispositivi offline e rientri online finiscono qui.</p>
                </div>
                <div class="alerts-feed" id="alertsFeed">
                    <?php if (empty($recentAlerts)): ?>
                    <div class="placeholder-card">Nessuna notifica recente.</div>
                    <?php else: ?>
                        <?php foreach ($recentAlerts as $alert): ?>
                        <div class="alert-item alert-<?php echo htmlspecialchars($alert['category']); ?>">
                            <div class="alert-icon"><i class="fas <?php echo renderAlertIcon($alert['category']); ?>"></i></div>
                            <div class="alert-content">
                                <strong><?php echo htmlspecialchars($alert['title']); ?></strong>
                                <p><?php echo htmlspecialchars($alert['message']); ?></p>
                                <span><?php echo htmlspecialchars($alert['created_at_label']); ?></span>
                            </div>
                        </div>
                        <?php endforeach; ?>
                    <?php endif; ?>
                </div>
            </div>
        </aside>

        <section class="devices-section">
            <?php if ($deviceError): ?>
            <div class="inline-banner banner-error">
                <i class="fas fa-circle-exclamation"></i>
                <span><?php echo htmlspecialchars($deviceError); ?></span>
            </div>
            <?php endif; ?>

            <div class="dashboard-header">
                <h1>Dispositivi di Rete</h1>
                <div class="header-actions">
                    <button class="btn-refresh" onclick="checkDevices()" id="btnRefresh">
                        <i class="fas fa-sync-alt"></i> Aggiorna Stato
                    </button>
                    <button class="btn-scan" onclick="scanNetwork()" id="btnScan" <?php echo $scanAvailable ? '' : 'disabled'; ?>>
                        <i class="fas fa-magnifying-glass"></i> Scansiona Rete
                    </button>
                    <button class="btn-add" onclick="openModal()">
                        <i class="fas fa-plus"></i> Aggiungi Dispositivo
                    </button>
                </div>
            </div>

            <div class="wow-grid">
                <div class="wow-card">
                    <div class="wow-card-header">
                        <h2>Vista rete</h2>
                        <span>
                            <?php
                            echo $scanAvailable
                                ? 'Subnet ' . htmlspecialchars($primarySubnet['network'])
                                : 'In attesa di una subnet IPv4';
                            ?>
                        </span>
                    </div>
                    <div class="network-visual">
                        <div class="network-core">
                            <i class="fas fa-network-wired"></i>
                            <strong>NetVision</strong>
                            <span><?php echo $metrics['total']; ?> nodi gestiti</span>
                        </div>
                        <div class="network-nodes">
                            <?php if (empty($topTypeCounts)): ?>
                            <div class="placeholder-card">Nessun gruppo di dispositivi disponibile.</div>
                            <?php else: ?>
                                <?php foreach ($topTypeCounts as $type => $count): ?>
                                <div class="network-node">
                                    <i class="fas <?php echo $typeIcons[$type] ?? 'fa-question-circle'; ?>"></i>
                                    <strong><?php echo htmlspecialchars($typeLabels[$type] ?? ucfirst($type)); ?></strong>
                                    <span><?php echo $count; ?> host</span>
                                </div>
                                <?php endforeach; ?>
                            <?php endif; ?>
                        </div>
                    </div>
                </div>

                <div class="wow-card">
                    <div class="wow-card-header">
                        <h2>Storico recente</h2>
                        <span>Ultimi cambi e controlli</span>
                    </div>
                    <div class="history-feed" id="historyFeed">
                        <?php if (empty($recentHistory)): ?>
                        <div class="placeholder-card">Lo storico apparira' dopo i primi controlli di stato.</div>
                        <?php else: ?>
                            <?php foreach ($recentHistory as $item): ?>
                            <div class="history-item">
                                <div class="history-main">
                                    <strong><?php echo htmlspecialchars($item['device_name']); ?></strong>
                                    <span><?php echo htmlspecialchars($item['device_ip']); ?></span>
                                </div>
                                <div class="history-meta">
                                    <span class="history-badge status-<?php echo htmlspecialchars($item['current_status']); ?>">
                                        <?php echo htmlspecialchars(ucfirst($item['current_status'])); ?>
                                    </span>
                                    <span><?php echo htmlspecialchars($item['checked_at_label']); ?></span>
                                    <span><?php echo htmlspecialchars($item['source']); ?></span>
                                </div>
                            </div>
                            <?php endforeach; ?>
                        <?php endif; ?>
                    </div>
                </div>
            </div>

            <?php if (empty($devices)): ?>
            <div class="empty-state">
                <i class="fas fa-network-wired"></i>
                <p>Nessun dispositivo aggiunto.</p>
                <button class="btn-add" onclick="openModal()">Aggiungi il primo dispositivo</button>
            </div>
            <?php else: ?>
            <div class="devices-grid">
                <?php foreach ($devices as $device): ?>
                    <?php
                    $icon = $typeIcons[$device['type']] ?? 'fa-question-circle';
                    $typeLabel = $typeLabels[$device['type']] ?? $device['type'];
                    $status = $device['status'];

                    if ($status === 'online') {
                        $statusClass = 'status-online';
                        $statusLabel = 'Online';
                    } elseif ($status === 'offline') {
                        $statusClass = 'status-offline';
                        $statusLabel = 'Offline';
                    } else {
                        $statusClass = 'status-unknown';
                        $statusLabel = 'Non verificato';
                    }

                    $lastCheck = nvFormatDateTime($device['last_check'] ?? null);
                    $deviceJson = htmlspecialchars(json_encode($device), ENT_QUOTES);
                    ?>
                <div class="device-card" id="card-<?php echo $device['id']; ?>">
                    <div class="card-icon <?php echo $statusClass; ?>-icon">
                        <i class="fas <?php echo $icon; ?>"></i>
                    </div>
                    <div class="card-body">
                        <h3 class="device-name"><?php echo htmlspecialchars($device['name']); ?></h3>
                        <p class="device-type"><?php echo htmlspecialchars($typeLabel); ?></p>
                        <p class="device-ip"><i class="fas fa-globe"></i> <?php echo htmlspecialchars($device['ip']); ?></p>
                        <div class="status-badge <?php echo $statusClass; ?>">
                            <span class="status-dot"></span>
                            <?php echo $statusLabel; ?>
                        </div>
                        <p class="last-check"><i class="fas fa-clock"></i> <?php echo htmlspecialchars($lastCheck); ?></p>
                    </div>
                    <div class="card-actions">
                        <button class="btn-edit" onclick='openEditModal(<?php echo $deviceJson; ?>)'>
                            <i class="fas fa-pen"></i> Modifica
                        </button>
                        <button class="btn-delete" onclick="deleteDevice(<?php echo $device['id']; ?>, '<?php echo htmlspecialchars($device['name'], ENT_QUOTES); ?>')">
                            <i class="fas fa-trash"></i> Elimina
                        </button>
                    </div>
                </div>
                <?php endforeach; ?>
            </div>
            <?php endif; ?>
        </section>
    </div>
</main>

<div class="modal-overlay" id="modalOverlay" onclick="closeModal(event)">
    <div class="modal">
        <div class="modal-header">
            <h2 id="modalTitle">Aggiungi Dispositivo</h2>
            <button class="modal-close" onclick="closeModal()"><i class="fas fa-times"></i></button>
        </div>
        <form method="POST" action="dashboard.php" id="deviceForm">
            <input type="hidden" name="action" id="formAction" value="add">
            <input type="hidden" name="id" id="formId" value="">
            <div class="form-group">
                <label>Nome Dispositivo</label>
                <input type="text" name="name" id="deviceName" placeholder="es. PC Ufficio" required>
            </div>
            <div class="form-group">
                <label>Indirizzo IP</label>
                <div class="input-with-help">
                    <input type="text" name="ip" id="deviceIp" placeholder="es. 192.168.1.100 oppure 2001:db8::10" required>
                    <span class="hint-icon" id="ipHintIcon" aria-hidden="true">?</span>
                </div>
            </div>
            <div class="form-group">
                <label>Tipo di Dispositivo</label>
                <select name="type" id="deviceType">
                    <option value="pc">PC</option>
                    <option value="laptop">Laptop</option>
                    <option value="server">Server</option>
                    <option value="router">Router</option>
                    <option value="switch">Switch</option>
                    <option value="printer">Stampante</option>
                    <option value="phone">Telefono</option>
                    <option value="camera">Telecamera</option>
                </select>
            </div>
            <div class="modal-footer">
                <button type="button" class="btn-cancel" onclick="closeModal()">Annulla</button>
                <button type="submit" class="btn-save">Salva</button>
            </div>
        </form>
    </div>
</div>

<form id="deleteForm" method="POST" action="dashboard.php">
    <input type="hidden" name="action" value="delete">
    <input type="hidden" name="id" id="deleteId">
</form>

<div id="toastHost" class="toast-host"></div>

<script>
function getScopedIpv6Base(value) {
    const parts = value.split('%');
    if (parts.length !== 2 || !parts[0] || !parts[1]) {
        return null;
    }

    if (!/^[A-Za-z0-9_.-]+$/.test(parts[1])) {
        return null;
    }

    return parts[0];
}

function isValidIpv4(value) {
    const parts = value.split('.');
    if (parts.length !== 4) {
        return false;
    }

    return parts.every(function(part) {
        return /^(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)$/.test(part);
    });
}

function isValidIpv6(value) {
    if (!value || /\s/.test(value)) {
        return false;
    }

    if (!/^[0-9A-Fa-f:]+$/.test(value)) {
        return false;
    }

    if ((value.match(/::/g) || []).length > 1) {
        return false;
    }

    const halves = value.split('::');
    const left = halves[0] ? halves[0].split(':').filter(Boolean) : [];
    const right = halves[1] ? halves[1].split(':').filter(Boolean) : [];
    const allGroups = left.concat(right);

    if (allGroups.some(function(group) {
        return !/^[0-9A-Fa-f]{1,4}$/.test(group);
    })) {
        return false;
    }

    if (halves.length === 1) {
        return allGroups.length === 8;
    }

    return allGroups.length < 8;
}

function isValidIpAddress(value) {
    if (!value) {
        return false;
    }

    if (isValidIpv4(value) || isValidIpv6(value)) {
        return true;
    }

    const baseIpv6 = getScopedIpv6Base(value);
    return baseIpv6 !== null && isValidIpv6(baseIpv6);
}

function updateIpValidation() {
    const ipInput = document.getElementById('deviceIp');
    const saveButton = document.querySelector('#deviceForm .btn-save');
    const value = ipInput.value.trim();

    if (value === '') {
        ipInput.classList.remove('is-valid', 'is-invalid');
        saveButton.disabled = true;
        return false;
    }

    if (isValidIpAddress(value)) {
        ipInput.classList.remove('is-invalid');
        ipInput.classList.add('is-valid');
        saveButton.disabled = false;
        return true;
    }

    ipInput.classList.remove('is-valid');
    ipInput.classList.add('is-invalid');
    saveButton.disabled = true;
    return false;
}

function openModal() {
    document.getElementById('modalTitle').textContent = 'Aggiungi Dispositivo';
    document.getElementById('formAction').value = 'add';
    document.getElementById('formId').value = '';
    document.getElementById('deviceName').value = '';
    document.getElementById('deviceIp').value = '';
    document.getElementById('deviceType').value = 'pc';
    document.getElementById('modalOverlay').classList.add('active');
    updateIpValidation();
}

function openEditModal(device) {
    document.getElementById('modalTitle').textContent = 'Modifica Dispositivo';
    document.getElementById('formAction').value = 'edit';
    document.getElementById('formId').value = device.id;
    document.getElementById('deviceName').value = device.name;
    document.getElementById('deviceIp').value = device.ip;
    document.getElementById('deviceType').value = device.type;
    document.getElementById('modalOverlay').classList.add('active');
    updateIpValidation();
}

function closeModal(event) {
    if (!event || event.target === document.getElementById('modalOverlay')) {
        document.getElementById('modalOverlay').classList.remove('active');
    }
}

function deleteDevice(id, name) {
    if (confirm('Eliminare "' + name + '"?')) {
        document.getElementById('deleteId').value = id;
        document.getElementById('deleteForm').submit();
    }
}

function showToast(message, variant) {
    const host = document.getElementById('toastHost');
    const toast = document.createElement('div');
    toast.className = 'toast-item toast-' + (variant || 'info');
    toast.textContent = message;
    host.appendChild(toast);

    setTimeout(function() {
        toast.classList.add('visible');
    }, 20);

    setTimeout(function() {
        toast.classList.remove('visible');
        setTimeout(function() {
            toast.remove();
        }, 220);
    }, 3200);
}

function renderAlertIcon(category) {
    if (category === 'device_offline') {
        return 'fa-triangle-exclamation';
    }

    if (category === 'device_online') {
        return 'fa-circle-check';
    }

    return 'fa-satellite-dish';
}

function renderAlerts(alerts) {
    const feed = document.getElementById('alertsFeed');
    if (!alerts || alerts.length === 0) {
        feed.innerHTML = '<div class="placeholder-card">Nessuna notifica recente.</div>';
        return;
    }

    feed.innerHTML = alerts.map(function(alert) {
        return '<div class="alert-item alert-' + alert.category + '">' +
            '<div class="alert-icon"><i class="fas ' + renderAlertIcon(alert.category) + '"></i></div>' +
            '<div class="alert-content">' +
                '<strong>' + escapeHtml(alert.title) + '</strong>' +
                '<p>' + escapeHtml(alert.message) + '</p>' +
                '<span>' + escapeHtml(alert.created_at_label) + '</span>' +
            '</div>' +
        '</div>';
    }).join('');
}

function renderHistory(history) {
    const feed = document.getElementById('historyFeed');
    if (!history || history.length === 0) {
        feed.innerHTML = '<div class="placeholder-card">Lo storico apparira\' dopo i primi controlli di stato.</div>';
        return;
    }

    feed.innerHTML = history.map(function(item) {
        return '<div class="history-item">' +
            '<div class="history-main">' +
                '<strong>' + escapeHtml(item.device_name) + '</strong>' +
                '<span>' + escapeHtml(item.device_ip) + '</span>' +
            '</div>' +
            '<div class="history-meta">' +
                '<span class="history-badge status-' + escapeHtml(item.current_status) + '">' + escapeHtml(capitalize(item.current_status)) + '</span>' +
                '<span>' + escapeHtml(item.checked_at_label) + '</span>' +
                '<span>' + escapeHtml(item.source) + '</span>' +
            '</div>' +
        '</div>';
    }).join('');
}

function updateText(id, value) {
    const el = document.getElementById(id);
    if (el) {
        el.textContent = value;
    }
}

function renderDashboardPanels(payload) {
    if (!payload) {
        return;
    }

    const metrics = payload.metrics || {};
    const subnet = payload.primary_subnet || null;

    updateText('metricTotal', metrics.total || 0);
    updateText('metricOnline', metrics.online || 0);
    updateText('metricOffline', metrics.offline || 0);
    updateText('metricHostsUsed', subnet ? (subnet.assigned_hosts + '/' + subnet.usable_hosts) : '0/0');
    updateText('detailNetwork', subnet ? subnet.network : 'Non disponibile');
    updateText('detailMask', subnet ? (subnet.mask + ' ' + subnet.cidr) : 'Non disponibile');
    updateText('detailRange', subnet ? subnet.host_range : 'Non disponibile');
    updateText('detailBroadcast', subnet ? subnet.broadcast : 'Non disponibile');
    updateText('detailGateway', subnet ? subnet.gateway : 'Non disponibile');
    updateText('detailType', subnet ? subnet.network_type : 'Non disponibile');

    const networkNote = document.getElementById('networkNote');
    if (networkNote) {
        if (subnet) {
            networkNote.innerHTML = '<p>Subnet principale rilevata da ' + subnet.assigned_hosts +
                ' dispositivi IPv4 su ' + subnet.usable_hosts + ' host disponibili.</p>';
        } else {
            networkNote.innerHTML = '<p>Aggiungi almeno un dispositivo con IPv4 per visualizzare pool, maschera e range host della rete.</p>';
        }
    }

    renderAlerts(payload.alerts || []);
    renderHistory(payload.history || []);
}

function checkDevices() {
    const btn = document.getElementById('btnRefresh');
    btn.disabled = true;
    btn.innerHTML = '<i class="fas fa-sync-alt fa-spin"></i> Aggiornamento...';

    fetch('api/check_devices.php')
        .then(function(response) {
            return response.json();
        })
        .then(function(data) {
            if (!data.success) {
                throw new Error(data.message || 'Aggiornamento non riuscito.');
            }

            let changedCount = 0;

            data.devices.forEach(function(device) {
                const card = document.getElementById('card-' + device.id);
                if (!card) {
                    return;
                }

                const badge = card.querySelector('.status-badge');
                const iconDiv = card.querySelector('.card-icon');
                const lastCheck = card.querySelector('.last-check');
                const labelMap = { online: 'Online', offline: 'Offline', unknown: 'Non verificato' };
                const cssClass = 'status-' + device.status;

                badge.className = 'status-badge ' + cssClass;
                badge.innerHTML = '<span class="status-dot"></span> ' + labelMap[device.status];
                iconDiv.className = 'card-icon ' + cssClass + '-icon';
                lastCheck.innerHTML = '<i class="fas fa-clock"></i> ' + escapeHtml(device.last_check);

                if (device.status_changed) {
                    changedCount++;
                }
            });

            renderDashboardPanels(data.dashboard);

            if (changedCount > 0) {
                showToast('Aggiornamento completato con ' + changedCount + ' cambi di stato.', 'success');
            } else {
                showToast('Stato dispositivi aggiornato.', 'info');
            }
        })
        .catch(function(error) {
            showToast(error.message || 'Errore durante l\'aggiornamento.', 'error');
        })
        .finally(function() {
            btn.disabled = false;
            btn.innerHTML = '<i class="fas fa-sync-alt"></i> Aggiorna Stato';
        });
}

function scanNetwork() {
    const btn = document.getElementById('btnScan');
    if (btn.disabled) {
        return;
    }

    btn.disabled = true;
    btn.innerHTML = '<i class="fas fa-magnifying-glass fa-spin"></i> Scansione...';

    fetch('api/scan_network.php')
        .then(function(response) {
            return response.json();
        })
        .then(function(data) {
            if (!data.success) {
                throw new Error(data.message || 'Scansione non riuscita.');
            }

            showToast(data.message, 'success');
            setTimeout(function() {
                window.location.reload();
            }, 900);
        })
        .catch(function(error) {
            showToast(error.message || 'Errore durante la scansione.', 'error');
            btn.disabled = false;
            btn.innerHTML = '<i class="fas fa-magnifying-glass"></i> Scansiona Rete';
        });
}

function capitalize(value) {
    return value.charAt(0).toUpperCase() + value.slice(1);
}

function escapeHtml(value) {
    return String(value)
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#039;');
}

setInterval(checkDevices, 60000);

document.getElementById('deviceIp').addEventListener('input', updateIpValidation);

document.getElementById('deviceForm').addEventListener('submit', function(event) {
    if (!updateIpValidation()) {
        event.preventDefault();
        document.getElementById('deviceIp').focus();
    }
});

updateIpValidation();

(function() {
    var icon = document.getElementById('ipHintIcon');
    var tooltip = document.createElement('div');
    tooltip.id = 'ipTooltip';
    tooltip.innerHTML =
        '<p>Controlla che l\'indirizzo sia scritto correttamente.</p>' +
        '<p>Per IPv4 usa il formato 192.168.1.10 con quattro gruppi separati da punti.</p>' +
        '<p>Per IPv6 evita spazi e caratteri extra; se necessario prova senza la parte dopo %, ad esempio fe80::1 invece di fe80::1%15.</p>' +
        '<p>Non inserire http://, https://, porte come :8080 o nomi host.</p>';
    tooltip.style.cssText =
        'display:none;position:fixed;background:#1f2937;color:#fff;' +
        'padding:12px 14px;border-radius:10px;font-size:0.82rem;line-height:1.5;' +
        'width:280px;box-shadow:0 8px 24px rgba(0,0,0,0.25);z-index:99999;pointer-events:none;';
    document.body.appendChild(tooltip);

    var lines = tooltip.getElementsByTagName('p');
    for (var i = 1; i < lines.length; i++) {
        lines[i].style.marginTop = '8px';
    }

    icon.addEventListener('mouseenter', function() {
        var rect = icon.getBoundingClientRect();
        tooltip.style.top = (rect.top + rect.height / 2 - 20) + 'px';
        tooltip.style.left = (rect.right + 10) + 'px';
        tooltip.style.display = 'block';
    });

    icon.addEventListener('mouseleave', function() {
        tooltip.style.display = 'none';
    });
})();
</script>
</body>
</html>
<?php
// Avvia la sessione
session_start();

// Se l'utente non è loggato lo reindirizza al login
if (!isset($_SESSION['logged_in'])) {
    header('Location: login.php');
    exit();
}

require 'includes/db.php';

function getScopedIpv6Base(string $address): ?string
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

function isValidIpAddress(string $address): bool
{
    if (filter_var($address, FILTER_VALIDATE_IP) !== false) {
        return true;
    }

    $baseIp = getScopedIpv6Base($address);
    if ($baseIp === null) {
        return false;
    }

    return filter_var($baseIp, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6) !== false;
}

function isIpv4Address(string $address): bool
{
    return filter_var($address, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4) !== false;
}

function isPrivateIpv4Address(string $address): bool
{
    if (!isIpv4Address($address)) {
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

function getPrimaryIpv4Subnet(array $devices): ?array
{
    $subnets = [];

    foreach ($devices as $device) {
        $ip = trim($device['ip'] ?? '');
        if (!isIpv4Address($ip)) {
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
                'network_type'   => isPrivateIpv4Address($ip) ? 'Privata (RFC1918)' : 'Pubblica o personalizzata',
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

// Crea la tabella devices se non esiste ancora
$con->query("CREATE TABLE IF NOT EXISTS devices (
    id INT AUTO_INCREMENT PRIMARY KEY,
    name VARCHAR(100) NOT NULL,
    ip VARCHAR(45) NOT NULL,
    type VARCHAR(50) NOT NULL DEFAULT 'pc',
    status ENUM('online','offline','unknown') NOT NULL DEFAULT 'unknown',
    last_check DATETIME DEFAULT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4");

// Gestisce le azioni inviate tramite POST (aggiungi, modifica, elimina)
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $action = $_POST['action'] ?? '';

    // Aggiunge un nuovo dispositivo
    if ($action === 'add') {
        $name   = trim($_POST['name']);
        $ip_dev = trim($_POST['ip']);
        $type   = $_POST['type'];
        if (isValidIpAddress($ip_dev)) {
            $stmt = $con->prepare("INSERT INTO devices (name, ip, type) VALUES (?, ?, ?)");
            $stmt->bind_param("sss", $name, $ip_dev, $type);
            $stmt->execute();
        } else {
            $_SESSION['device_error'] = 'Inserisci un indirizzo IP valido IPv4 o IPv6.';
        }

    // Modifica un dispositivo esistente
    } elseif ($action === 'edit') {
        $id     = (int)$_POST['id'];
        $name   = trim($_POST['name']);
        $ip_dev = trim($_POST['ip']);
        $type   = $_POST['type'];
        if (isValidIpAddress($ip_dev)) {
            $stmt = $con->prepare("UPDATE devices SET name=?, ip=?, type=? WHERE id=?");
            $stmt->bind_param("sssi", $name, $ip_dev, $type, $id);
            $stmt->execute();
        } else {
            $_SESSION['device_error'] = 'Inserisci un indirizzo IP valido IPv4 o IPv6.';
        }

    // Elimina un dispositivo
    } elseif ($action === 'delete') {
        $id = (int)$_POST['id'];
        $stmt = $con->prepare("DELETE FROM devices WHERE id=?");
        $stmt->bind_param("i", $id);
        $stmt->execute();
    }

    // Dopo ogni azione reindirizza alla dashboard per evitare reinvii del form
    header('Location: dashboard.php');
    exit();
}

// Recupera tutti i dispositivi dal database ordinati per nome
$result  = $con->query("SELECT * FROM devices ORDER BY name ASC");
$devices = $result ? $result->fetch_all(MYSQLI_ASSOC) : [];
$primarySubnet = getPrimaryIpv4Subnet($devices);
$onlineDevices = 0;
$offlineDevices = 0;
$unknownDevices = 0;
$ipv4Count = 0;

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
    if (isIpv4Address($ip)) {
        $ipv4Count++;
    }
}

// Mappa tipo dispositivo -> icona Font Awesome
$typeIcons = [
    'pc'      => 'fa-desktop',
    'laptop'  => 'fa-laptop',
    'server'  => 'fa-server',
    'router'  => 'fa-wifi',
    'switch'  => 'fa-network-wired',
    'printer' => 'fa-print',
    'phone'   => 'fa-mobile-alt',
    'camera'  => 'fa-camera',
];

// Mappa tipo dispositivo -> etichetta in italiano
$typeLabels = [
    'pc'      => 'PC',
    'laptop'  => 'Laptop',
    'server'  => 'Server',
    'router'  => 'Router',
    'switch'  => 'Switch',
    'printer' => 'Stampante',
    'phone'   => 'Telefono',
    'camera'  => 'Telecamera',
];
?>
<!DOCTYPE html>
<html lang="it">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>NetVision - Dashboard</title>
    <link rel="stylesheet" href="assets/css/dashboard.css">
    <!-- Font Awesome per le icone dei dispositivi -->
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.0/css/all.min.css">
</head>
<body>

<!-- Barra superiore con logo e info utente -->
<header class="topbar">
    <div class="topbar-left">
        <span class="topbar-logo">NetVision</span>
    </div>
    <div class="topbar-right">
        <span class="topbar-user"><i class="fas fa-user"></i> <?php echo htmlspecialchars($_SESSION['username']); ?></span>
        <a href="login.php" class="btn-logout"><i class="fas fa-sign-out-alt"></i> Esci</a>
    </div>
</header>

<main class="main-content">
    <div class="dashboard-layout">
        <aside class="network-sidebar">
            <div class="network-panel">
                <div class="network-panel-header">
                    <span class="panel-kicker">Panoramica</span>
                    <h2>Informazioni di rete</h2>
                    <p>Un riepilogo rapido della rete e dello stato dei dispositivi.</p>
                </div>

                <div class="network-stat-grid">
                    <div class="network-stat-card">
                        <span class="network-stat-label">Dispositivi</span>
                        <strong><?php echo count($devices); ?></strong>
                    </div>
                    <div class="network-stat-card">
                        <span class="network-stat-label">Host usati</span>
                        <strong>
                            <?php
                            echo $primarySubnet
                                ? $primarySubnet['assigned_hosts'] . '/' . $primarySubnet['usable_hosts']
                                : '0/0';
                            ?>
                        </strong>
                    </div>
                    <div class="network-stat-card">
                        <span class="network-stat-label">Online</span>
                        <strong><?php echo $onlineDevices; ?></strong>
                    </div>
                    <div class="network-stat-card">
                        <span class="network-stat-label">Offline</span>
                        <strong><?php echo $offlineDevices; ?></strong>
                    </div>
                </div>

                <div class="network-details">
                    <div class="network-detail-row">
                        <span>Pool IP principale</span>
                        <strong><?php echo htmlspecialchars($primarySubnet['network'] ?? 'Non disponibile'); ?></strong>
                    </div>
                    <div class="network-detail-row">
                        <span>Maschera</span>
                        <strong>
                            <?php
                            echo $primarySubnet
                                ? htmlspecialchars($primarySubnet['mask'] . ' ' . $primarySubnet['cidr'])
                                : 'Non disponibile';
                            ?>
                        </strong>
                    </div>
                    <div class="network-detail-row">
                        <span>Range host</span>
                        <strong><?php echo htmlspecialchars($primarySubnet['host_range'] ?? 'Non disponibile'); ?></strong>
                    </div>
                    <div class="network-detail-row">
                        <span>Broadcast</span>
                        <strong><?php echo htmlspecialchars($primarySubnet['broadcast'] ?? 'Non disponibile'); ?></strong>
                    </div>
                    <div class="network-detail-row">
                        <span>Gateway suggerito</span>
                        <strong><?php echo htmlspecialchars($primarySubnet['gateway'] ?? 'Non disponibile'); ?></strong>
                    </div>
                    <div class="network-detail-row">
                        <span>Tipo rete</span>
                        <strong><?php echo htmlspecialchars($primarySubnet['network_type'] ?? 'Non disponibile'); ?></strong>
                    </div>
                </div>

                <div class="network-note">
                    <?php if ($primarySubnet): ?>
                    <p>
                        Subnet principale rilevata da <?php echo $primarySubnet['assigned_hosts']; ?>
                        dispositiv<?php echo $primarySubnet['assigned_hosts'] === 1 ? 'o' : 'i'; ?>
                        IPv4 su <?php echo $primarySubnet['usable_hosts']; ?> host disponibili.
                    </p>
                    <?php else: ?>
                    <p>Aggiungi almeno un dispositivo con IPv4 per visualizzare pool, maschera e range host della rete.</p>
                    <?php endif; ?>
                </div>
            </div>
        </aside>

        <section class="devices-section">
            <div class="dashboard-header">
                <h1>Dispositivi di Rete</h1>
                <div class="header-actions">
                    <button class="btn-refresh" onclick="checkDevices()" id="btnRefresh">
                        <i class="fas fa-sync-alt"></i> Aggiorna Stato
                    </button>
                    <button class="btn-add" onclick="openModal()">
                        <i class="fas fa-plus"></i> Aggiungi Dispositivo
                    </button>
                </div>
            </div>

            <?php if (empty($devices)): ?>
            <div class="empty-state">
                <i class="fas fa-network-wired"></i>
                <p>Nessun dispositivo aggiunto.</p>
                <button class="btn-add" onclick="openModal()">Aggiungi il primo dispositivo</button>
            </div>
            <?php else: ?>
            <div class="devices-grid">
                <?php foreach ($devices as $device):
                    $icon      = $typeIcons[$device['type']]  ?? 'fa-question-circle';
                    $typeLabel = $typeLabels[$device['type']] ?? $device['type'];
                    $status    = $device['status'];

                    if ($status === 'online') {
                        $statusClass = 'status-online';
                        $statusLabel = 'Online';
                    } elseif ($status === 'offline') {
                        $statusClass = 'status-offline';
                        $statusLabel = 'Offline';
                    } else {
                        $statusClass = 'status-unknown';
                        $statusLabel = 'Non verificato';
                    }

                    if ($device['last_check']) {
                        $lastCheck = date('d/m/Y H:i', strtotime($device['last_check']));
                    } else {
                        $lastCheck = 'Mai';
                    }

                    $deviceJson = htmlspecialchars(json_encode($device), ENT_QUOTES);
                ?>
                <div class="device-card" id="card-<?php echo $device['id']; ?>">
                    <div class="card-icon <?php echo $statusClass; ?>-icon">
                        <i class="fas <?php echo $icon; ?>"></i>
                    </div>
                    <div class="card-body">
                        <h3 class="device-name"><?php echo htmlspecialchars($device['name']); ?></h3>
                        <p class="device-type"><?php echo $typeLabel; ?></p>
                        <p class="device-ip"><i class="fas fa-globe"></i> <?php echo htmlspecialchars($device['ip']); ?></p>
                        <div class="status-badge <?php echo $statusClass; ?>">
                            <span class="status-dot"></span>
                            <?php echo $statusLabel; ?>
                        </div>
                        <p class="last-check"><i class="fas fa-clock"></i> <?php echo $lastCheck; ?></p>
                    </div>
                    <div class="card-actions">
                        <button class="btn-edit" onclick='openEditModal(<?php echo $deviceJson; ?>)'>
                            <i class="fas fa-pen"></i> Modifica
                        </button>
                        <button class="btn-delete" onclick="deleteDevice(<?php echo $device['id']; ?>, '<?php echo htmlspecialchars($device['name'], ENT_QUOTES); ?>')">
                            <i class="fas fa-trash"></i> Elimina
                        </button>
                    </div>
                </div>
                <?php endforeach; ?>
            </div>
            <?php endif; ?>
        </section>
    </div>
</main>

<!-- Modal per aggiungere o modificare un dispositivo -->
<div class="modal-overlay" id="modalOverlay" onclick="closeModal(event)">
    <div class="modal">
        <div class="modal-header">
            <h2 id="modalTitle">Aggiungi Dispositivo</h2>
            <button class="modal-close" onclick="closeModal()"><i class="fas fa-times"></i></button>
        </div>
        <form method="POST" action="dashboard.php" id="deviceForm">
            <!-- Campo nascosto per indicare l'azione (add o edit) -->
            <input type="hidden" name="action" id="formAction" value="add">
            <!-- Campo nascosto per l'id del dispositivo da modificare -->
            <input type="hidden" name="id" id="formId" value="">
            <div class="form-group">
                <label>Nome Dispositivo</label>
                <input type="text" name="name" id="deviceName" placeholder="es. PC Ufficio" required>
            </div>
            <div class="form-group">
                <label>Indirizzo IP</label>
                <div class="input-with-help">
                    <input type="text" name="ip" id="deviceIp" placeholder="es. 192.168.1.100 oppure 2001:db8::10" required>
                    <span class="hint-icon" id="ipHintIcon" aria-hidden="true">?</span>
                </div>
            </div>
            <div class="form-group">
                <label>Tipo di Dispositivo</label>
                <select name="type" id="deviceType">
                    <option value="pc">PC</option>
                    <option value="laptop">Laptop</option>
                    <option value="server">Server</option>
                    <option value="router">Router</option>
                    <option value="switch">Switch</option>
                    <option value="printer">Stampante</option>
                    <option value="phone">Telefono</option>
                    <option value="camera">Telecamera</option>
                </select>
            </div>
            <div class="modal-footer">
                <button type="button" class="btn-cancel" onclick="closeModal()">Annulla</button>
                <button type="submit" class="btn-save">Salva</button>
            </div>
        </form>
    </div>
</div>

<!-- Form nascosto usato per inviare la richiesta di eliminazione -->
<form id="deleteForm" method="POST" action="dashboard.php">
    <input type="hidden" name="action" value="delete">
    <input type="hidden" name="id" id="deleteId">
</form>

<script>
function getScopedIpv6Base(value) {
    const parts = value.split('%');
    if (parts.length !== 2 || !parts[0] || !parts[1]) {
        return null;
    }

    if (!/^[A-Za-z0-9_.-]+$/.test(parts[1])) {
        return null;
    }

    return parts[0];
}

function isValidIpv4(value) {
    const parts = value.split('.');
    if (parts.length !== 4) {
        return false;
    }

    return parts.every(function(part) {
        return /^(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)$/.test(part);
    });
}

function isValidIpv6(value) {
    if (!value || /\s/.test(value)) {
        return false;
    }

    if (!/^[0-9A-Fa-f:]+$/.test(value)) {
        return false;
    }

    if ((value.match(/::/g) || []).length > 1) {
        return false;
    }

    const halves = value.split('::');
    const left = halves[0] ? halves[0].split(':').filter(Boolean) : [];
    const right = halves[1] ? halves[1].split(':').filter(Boolean) : [];
    const allGroups = left.concat(right);

    if (allGroups.some(function(group) {
        return !/^[0-9A-Fa-f]{1,4}$/.test(group);
    })) {
        return false;
    }

    if (halves.length === 1) {
        return allGroups.length === 8;
    }

    return allGroups.length < 8;
}

function isValidIpAddress(value) {
    if (!value) {
        return false;
    }

    if (isValidIpv4(value) || isValidIpv6(value)) {
        return true;
    }

    const baseIpv6 = getScopedIpv6Base(value);
    return baseIpv6 !== null && isValidIpv6(baseIpv6);
}

function updateIpValidation() {
    const ipInput = document.getElementById('deviceIp');
    const saveButton = document.querySelector('#deviceForm .btn-save');
    const value = ipInput.value.trim();

    if (value === '') {
        ipInput.classList.remove('is-valid', 'is-invalid');
        saveButton.disabled = true;
        return false;
    }

    if (isValidIpAddress(value)) {
        ipInput.classList.remove('is-invalid');
        ipInput.classList.add('is-valid');
        saveButton.disabled = false;
        return true;
    }

    ipInput.classList.remove('is-valid');
    ipInput.classList.add('is-invalid');
    saveButton.disabled = true;
    return false;
}

// Apre il modal in modalità "aggiungi" resettando tutti i campi
function openModal() {
    document.getElementById('modalTitle').textContent = 'Aggiungi Dispositivo';
    document.getElementById('formAction').value = 'add';
    document.getElementById('formId').value     = '';
    document.getElementById('deviceName').value = '';
    document.getElementById('deviceIp').value   = '';
    document.getElementById('deviceType').value = 'pc';
    document.getElementById('modalOverlay').classList.add('active');
    updateIpValidation();
}

// Apre il modal in modalità "modifica" precompilando i campi con i dati del dispositivo
function openEditModal(device) {
    document.getElementById('modalTitle').textContent = 'Modifica Dispositivo';
    document.getElementById('formAction').value = 'edit';
    document.getElementById('formId').value     = device.id;
    document.getElementById('deviceName').value = device.name;
    document.getElementById('deviceIp').value   = device.ip;
    document.getElementById('deviceType').value = device.type;
    document.getElementById('modalOverlay').classList.add('active');
    updateIpValidation();
}

// Chiude il modal cliccando sulla X o sull'overlay esterno
function closeModal(event) {
    if (!event || event.target === document.getElementById('modalOverlay')) {
        document.getElementById('modalOverlay').classList.remove('active');
    }
}

// Chiede conferma e invia il form di eliminazione del dispositivo
function deleteDevice(id, name) {
    if (confirm('Eliminare "' + name + '"?')) {
        document.getElementById('deleteId').value = id;
        document.getElementById('deleteForm').submit();
    }
}

// Chiama check_devices.php via AJAX per aggiornare lo stato di tutti i dispositivi
function checkDevices() {
    const btn = document.getElementById('btnRefresh');

    // Disabilita il pulsante e mostra l'icona di caricamento
    btn.disabled = true;
    btn.innerHTML = '<i class="fas fa-sync-alt fa-spin"></i> Aggiornamento...';

    fetch('api/check_devices.php')
        .then(r => r.json())
        .then(data => {
            // Per ogni dispositivo aggiorna badge, colore icona e orario sulla card
            data.forEach(d => {
                const card = document.getElementById('card-' + d.id);
                if (!card) return;

                const badge     = card.querySelector('.status-badge');
                const iconDiv   = card.querySelector('.card-icon');
                const lastCheck = card.querySelector('.last-check');

                const labelMap = { online: 'Online', offline: 'Offline' };
                const label    = labelMap[d.status] || 'Non verificato';
                const cls      = 'status-' + d.status;

                badge.className     = 'status-badge ' + cls;
                badge.innerHTML     = '<span class="status-dot"></span> ' + label;
                iconDiv.className   = 'card-icon ' + cls + '-icon';
                lastCheck.innerHTML = '<i class="fas fa-clock"></i> ' + d.last_check;
            });
        })
        .finally(() => {
            // Riabilita il pulsante al termine
            btn.disabled = false;
            btn.innerHTML = '<i class="fas fa-sync-alt"></i> Aggiorna Stato';
        });
}

// Aggiorna automaticamente lo stato dei dispositivi ogni 60 secondi
setInterval(checkDevices, 60000);

document.getElementById('deviceIp').addEventListener('input', updateIpValidation);

document.getElementById('deviceForm').addEventListener('submit', function(event) {
    if (!updateIpValidation()) {
        event.preventDefault();
        document.getElementById('deviceIp').focus();
    }
});

updateIpValidation();

(function() {
    var icon = document.getElementById('ipHintIcon');

    var tooltip = document.createElement('div');
    tooltip.id = 'ipTooltip';
    tooltip.innerHTML =
        '<p>Controlla che l\'indirizzo sia scritto correttamente.</p>' +
        '<p>Per IPv4 usa il formato 192.168.1.10 con quattro gruppi separati da punti.</p>' +
        '<p>Per IPv6 evita spazi e caratteri extra; se necessario prova senza la parte dopo %, ad esempio fe80::1 invece di fe80::1%15.</p>' +
        '<p>Non inserire http://, https://, porte come :8080 o nomi host.</p>';
    tooltip.style.cssText =
        'display:none;position:fixed;background:#1f2937;color:#fff;' +
        'padding:12px 14px;border-radius:10px;font-size:0.82rem;line-height:1.5;' +
        'width:280px;box-shadow:0 8px 24px rgba(0,0,0,0.25);z-index:99999;pointer-events:none;';
    tooltip.querySelectorAll = null;
    document.body.appendChild(tooltip);

    var lines = tooltip.getElementsByTagName('p');
    for (var i = 1; i < lines.length; i++) {
        lines[i].style.marginTop = '8px';
    }

    icon.addEventListener('mouseenter', function() {
        var rect = icon.getBoundingClientRect();
        tooltip.style.top  = (rect.top + rect.height / 2 - 20) + 'px';
        tooltip.style.left = (rect.right + 10) + 'px';
        tooltip.style.display = 'block';
    });

    icon.addEventListener('mouseleave', function() {
        tooltip.style.display = 'none';
    });
})();
</script>

</body>
</html>
