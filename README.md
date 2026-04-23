# NetVision

Applicazione web per il monitoraggio dei dispositivi di rete locale.  
Permette di aggiungere dispositivi tramite indirizzo IP (IPv4 e IPv6), controllarne lo stato in tempo reale via ping e gestirli da una dashboard.

## Funzionalità

- Registrazione e login utenti
- Aggiunta, modifica ed eliminazione di dispositivi di rete
- Supporto indirizzi IPv4 e IPv6 (inclusi link-local con scope ID `%n`)
- Controllo stato online/offline tramite ping automatico
- Aggiornamento stato in tempo reale via AJAX ogni 60 secondi
- Validazione IP lato client e lato server

## Requisiti

- [XAMPP](https://www.apachefriends.org/) (Apache + PHP + MySQL) oppure qualsiasi stack LAMP/WAMP
- PHP >= 7.4
- MySQL >= 5.7

## Installazione

1. Clona il repository nella cartella `htdocs` di XAMPP:
   ```bash
   git clone https://github.com/sbromos/NetVision.git
   ```

2. Importa lo schema del database in **phpMyAdmin** o da terminale:
   ```bash
   mysql -u root -p < database.sql
   ```

3. Avvia Apache e MySQL da XAMPP Control Panel.

4. Apri il browser e vai su:
   ```
   http://localhost/NetVision/login.php
   ```

5. Registra un account e accedi.

## Struttura del progetto

```
NetVision/
├── css/
│   ├── login.css       # Stili per login e registrazione
│   └── dashboard.css   # Stili per la dashboard
├── login.php           # Pagina di login
├── register.php        # Pagina di registrazione
├── dashboard.php       # Dashboard principale
├── check_devices.php   # Controllo ping dispositivi (chiamato via AJAX)
├── database.sql        # Schema del database
└── README.md
```

## Note

Le credenziali del database sono configurate direttamente nei file PHP (`localhost`, utente `root`, password vuota) per uso locale con XAMPP.  
In produzione è consigliabile spostare la configurazione in un file separato non versionato.
