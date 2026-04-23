<?php
// La risposta viene restituita in formato JSON
header('Content-Type: application/json');

require '../includes/db.php';

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

function getIpPingFlag(string $address): ?string
{
    if (filter_var($address, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
        return '-4';
    }

    if (filter_var($address, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6)) {
        return '-6';
    }

    $baseIp = getScopedIpv6Base($address);
    if ($baseIp !== null && filter_var($baseIp, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6)) {
        return '-6';
    }

    return null;
}

// Recupera tutti i dispositivi dal database (id e ip)
$result = $con->query("SELECT id, ip FROM devices");

// Se la query fallisce restituisce un array vuoto e termina
if (!$result) {
    echo json_encode([]);
    exit();
}

// Salva tutti i dispositivi in un array
// fetch_all(MYSQLI_ASSOC) recupera tutte le righe del risultato e le mette in un array PHP.
// MYSQLI_ASSOC indica che ogni riga è un array associativo, cioè si accede ai dati
// tramite il nome della colonna (es. $device['ip'], $device['id']) invece che tramite indice numerico.
$devices = $result->fetch_all(MYSQLI_ASSOC);

// Array che conterrà i risultati da restituire come JSON
$output = [];

// Cicla su ogni dispositivo per controllarne la raggiungibilità
foreach ($devices as $device) {
    $pingFlag = getIpPingFlag($device['ip']);
    $returnCode = 1;

    // exec() esegue un comando di sistema. Il ping viene fatto con:
    // -4 / -6 → forza rispettivamente IPv4 o IPv6.
    // -n 1 → invia solo 1 pacchetto, -w 500 → timeout di 500ms.
    // $pingOut raccoglie l'output testuale del comando.
    // $returnCode contiene l'esito: 0 = ping riuscito (online), diverso da 0 = fallito (offline).
    // escapeshellarg() protegge l'IP da comandi malevoli inseriti nell'indirizzo.
    if ($pingFlag !== null) {
        $pingOut = [];
        exec("ping {$pingFlag} -n 1 -w 500 " . escapeshellarg($device['ip']), $pingOut, $returnCode);
    }

    // Se il ping ha successo (codice 0) il dispositivo è online, altrimenti offline
    if ($returnCode === 0) {
        $status = 'online';
    } else {
        $status = 'offline';
    }

    // Salva la data e ora attuale del controllo
    $now = date('Y-m-d H:i:s');

    // Aggiorna lo stato e l'ora dell'ultimo controllo nel database
    $stmt = $con->prepare("UPDATE devices SET status = ?, last_check = ? WHERE id = ?");
    $stmt->bind_param("ssi", $status, $now, $device['id']);
    $stmt->execute();

    // Aggiunge il risultato del dispositivo all'array di output
    $output[] = [
        'id'         => $device['id'],
        'status'     => $status,
        'last_check' => date('d/m/Y H:i', strtotime($now)),
    ];
}

// Restituisce tutti i risultati in formato JSON
echo json_encode($output);
