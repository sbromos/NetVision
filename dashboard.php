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
    <!-- Intestazione con titolo e pulsanti azione -->
    <div class="dashboard-header">
        <h1>Dispositivi di Rete</h1>
        <div class="header-actions">
            <!-- Pulsante che chiama check_devices.php via AJAX per aggiornare gli stati -->
            <button class="btn-refresh" onclick="checkDevices()" id="btnRefresh">
                <i class="fas fa-sync-alt"></i> Aggiorna Stato
            </button>
            <!-- Pulsante che apre il modal per aggiungere un dispositivo -->
            <button class="btn-add" onclick="openModal()">
                <i class="fas fa-plus"></i> Aggiungi Dispositivo
            </button>
        </div>
    </div>

    <?php if (empty($devices)): ?>
    <!-- Messaggio mostrato quando non ci sono dispositivi -->
    <div class="empty-state">
        <i class="fas fa-network-wired"></i>
        <p>Nessun dispositivo aggiunto.</p>
        <button class="btn-add" onclick="openModal()">Aggiungi il primo dispositivo</button>
    </div>
    <?php else: ?>
    <!-- Griglia con le card di tutti i dispositivi -->
    <div class="devices-grid">
        <?php foreach ($devices as $device):
            // Determina l'icona in base al tipo del dispositivo
            $icon      = $typeIcons[$device['type']]  ?? 'fa-question-circle';
            $typeLabel = $typeLabels[$device['type']] ?? $device['type'];
            $status    = $device['status'];

            // Determina la classe CSS e l'etichetta in base allo stato
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

            // Formatta la data dell'ultimo controllo
            if ($device['last_check']) {
                $lastCheck = date('d/m/Y H:i', strtotime($device['last_check']));
            } else {
                $lastCheck = 'Mai';
            }

            // Serializza i dati del dispositivo in JSON per passarli al JavaScript del modal
            $deviceJson = htmlspecialchars(json_encode($device), ENT_QUOTES);
        ?>
        <div class="device-card" id="card-<?php echo $device['id']; ?>">
            <!-- Icona del dispositivo con colore che riflette lo stato -->
            <div class="card-icon <?php echo $statusClass; ?>-icon">
                <i class="fas <?php echo $icon; ?>"></i>
            </div>
            <div class="card-body">
                <h3 class="device-name"><?php echo htmlspecialchars($device['name']); ?></h3>
                <p class="device-type"><?php echo $typeLabel; ?></p>
                <p class="device-ip"><i class="fas fa-globe"></i> <?php echo htmlspecialchars($device['ip']); ?></p>
                <!-- Badge colorato con lo stato del dispositivo -->
                <div class="status-badge <?php echo $statusClass; ?>">
                    <span class="status-dot"></span>
                    <?php echo $statusLabel; ?>
                </div>
                <!-- Data e ora dell'ultimo controllo ping -->
                <p class="last-check"><i class="fas fa-clock"></i> <?php echo $lastCheck; ?></p>
            </div>
            <!-- Pulsanti visibili al passaggio del mouse sulla card -->
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
