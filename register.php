<!DOCTYPE html>

<?php

// Parametri di connessione al database
$ip = 'localhost';
$user = 'root';
$pwd = '';
$dbname = 'NetVision';

// Connessione al database
$con = new mysqli($ip, $user, $pwd, $dbname);

?>

<html lang="it">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>NetVision - Registrazione</title>
    <link rel="stylesheet" href="css/login.css">
</head>
<body>
    <?php
        // Se il form non è ancora stato inviato, mostra il form di registrazione
        if(!isset($_POST['Registra'])){
            ?>
                <div class="login-container">
                    <h2>NetVision</h2>
                    <p class="register-subtitle">Crea il tuo account</p>
                    <form method="POST" action="<?php echo $_SERVER['PHP_SELF'] ?>">
                        <div class="form-group">
                            <label for="username">Nome Utente</label>
                            <input type="text" id="username" name="username" placeholder="Scegli un nome utente" required>
                        </div>
                        <div class="form-group">
                            <label for="password">Password</label>
                            <input type="password" id="password" name="password" placeholder="Scegli una password" required>
                        </div>
                        <div class="form-group">
                            <label for="password_confirm">Conferma Password</label>
                            <input type="password" id="password_confirm" name="password_confirm" placeholder="Ripeti la password" required>
                        </div>
                        <!-- Link alla pagina di login -->
                        <p class="register-hint">Hai già un account? <a href="login.php">Accedi</a></p>
                        <button type="submit" name="Registra" class="btn-login">REGISTRATI</button>
                    </form>
                </div>
        <?php
        }

        // Se il form è stato inviato, elabora la registrazione
        else {
            // Recupera i dati inseriti dall'utente
            $username        = trim($_POST['username']);
            $password        = $_POST['password'];
            $passwordConfirm = $_POST['password_confirm'];

            // Variabile che conterrà il messaggio di errore (vuota se non ci sono errori)
            $errore = '';

            // Controlla che i campi non siano vuoti
            if(empty($username) || empty($password)){
                $errore = 'Compila tutti i campi.';

            // Controlla che le due password coincidano
            } elseif($password !== $passwordConfirm){
                $errore = 'Le password non coincidono.';

            // Controlla che la password sia lunga almeno 6 caratteri
            } elseif(strlen($password) < 6){
                $errore = 'La password deve essere di almeno 6 caratteri.';

            } else {
                // Controlla se lo username è già presente nel database
                $stmtCheck = $con->prepare("SELECT id FROM users WHERE username = ?");
                $stmtCheck->bind_param("s", $username);
                $stmtCheck->execute();
                $stmtCheck->store_result();

                if($stmtCheck->num_rows > 0){
                    // Username già in uso
                    $errore = 'Nome utente già in uso. Scegline un altro.';
                } else {
                    // Inserisce il nuovo utente nel database
                    $stmtInsert = $con->prepare("INSERT INTO users (username, password) VALUES (?, ?)");
                    $stmtInsert->bind_param("ss", $username, $password);

                    if($stmtInsert->execute()){
                        // Registrazione riuscita: mostra messaggio di successo e pulsante per andare al login
                        ?>
                        <div class="toast toast-success" id="toast">Registrazione avvenuta con successo!</div>
                        <div class="login-container">
                            <h2>NetVision</h2>
                            <p class="register-subtitle success-text">Benvenuto, <strong><?php echo $username; ?></strong>!</p>
                            <p class="register-hint" style="text-align:center; margin-top: 20px;">
                                <a href="login.php" class="btn-login" style="display:block; text-decoration:none; text-align:center;">VAI AL LOGIN</a>
                            </p>
                        </div>
                        <script>
                            // Mostra il toast verde di successo e lo nasconde dopo 3.5 secondi
                            var t = document.getElementById('toast');
                            setTimeout(function(){ t.classList.add('show'); }, 50);
                            setTimeout(function(){ t.classList.remove('show'); }, 3500);
                        </script>
                        <?php
                        exit();
                    } else {
                        // Errore generico durante l'inserimento nel database
                        $errore = 'Errore durante la registrazione. Riprova.';
                    }
                }
            }

            // Mostra il toast di errore e il form di nuovo con lo username già inserito
            ?>
            <div class="toast" id="toast"><?php echo htmlspecialchars($errore); ?></div>
            <div class="login-container">
                <h2>NetVision</h2>
                <p class="register-subtitle">Crea il tuo account</p>
                <form method="POST" action="<?php echo $_SERVER['PHP_SELF'] ?>">
                    <div class="form-group">
                        <label for="username">Nome Utente</label>
                        <!-- Il valore viene ripopolato per non far ridigitare lo username -->
                        <input type="text" id="username" name="username" placeholder="Scegli un nome utente"
                               value="<?php echo htmlspecialchars($username); ?>" required>
                    </div>
                    <div class="form-group">
                        <label for="password">Password</label>
                        <input type="password" id="password" name="password" placeholder="Scegli una password" required>
                    </div>
                    <div class="form-group">
                        <label for="password_confirm">Conferma Password</label>
                        <input type="password" id="password_confirm" name="password_confirm" placeholder="Ripeti la password" required>
                    </div>
                    <!-- Link alla pagina di login -->
                    <p class="register-hint">Hai già un account? <a href="login.php">Accedi</a></p>
                    <button type="submit" name="Registra" class="btn-login">REGISTRATI</button>
                </form>
            </div>
            <script>
                // Mostra il toast di errore dopo 50ms e lo nasconde dopo 3.5 secondi
                var t = document.getElementById('toast');
                setTimeout(function(){ t.classList.add('show'); }, 50);
                setTimeout(function(){ t.classList.remove('show'); }, 3500);
            </script>
            <?php
        }
    ?>
</body>
</html>
