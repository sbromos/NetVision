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
    <title>NetVision - Login</title>
    <link rel="stylesheet" href="css/login.css">
</head>
<body>
    <?php
        // Avvia la sessione
        session_start();

        // Se il form non è ancora stato inviato, mostra il form di login
        if(!isset($_POST['Invia'])){
            ?>
                <div class="login-container">
                    <h2>NetVision</h2>
                    <form method="POST" action="<?php echo $_SERVER['PHP_SELF'] ?>">
                        <div class="form-group">
                            <label for="username">Nome Utente</label>
                            <input type="text" id="username" name="username" placeholder="Inserisci il nome utente" required>
                        </div>
                        <div class="form-group">
                            <label for="password">Password</label>
                            <input type="password" id="password" name="password" placeholder="Inserisci la password" required>
                        </div>
                        <!-- Link alla pagina di registrazione -->
                        <p class="register-hint">Non sei ancora registrato? <a href="register.php">Registrati</a></p>
                        <button type="submit" name="Invia" class="btn-login">ACCEDI</button>
                    </form>
                </div>
        <?php
        }

        // Se il form è stato inviato, controlla le credenziali
        else{
            // Recupera i dati inseriti dall'utente
            $username = $_POST['username'];
            $password = $_POST['password'];

            // Cerca l'utente nel database con username e password corrispondenti
            $stmt = $con->prepare("SELECT * FROM users WHERE username = ? AND password = ?");
            $stmt->bind_param("ss", $username, $password);
            $stmt->execute();
            $result = $stmt->get_result();

            // Se trova almeno un risultato le credenziali sono corrette
            if($result->num_rows > 0){
                // Salva i dati nella sessione e reindirizza alla dashboard
                $_SESSION['logged_in'] = true;
                $_SESSION['username'] = $username;
                header('Location: dashboard.php');
                exit();
                
            } else {
                // Credenziali errate: mostra il toast di errore e il form di nuovo
                ?>
                <div class="toast" id="toast">Nome utente o password errati.</div>
                <div class="login-container">
                    <h2>NetVision</h2>
                    <form method="POST" action="<?php echo $_SERVER['PHP_SELF'] ?>">
                        <div class="form-group">
                            <label for="username">Nome Utente</label>
                            <input type="text" id="username" name="username" placeholder="Inserisci il nome utente" required>
                        </div>
                        <div class="form-group">
                            <label for="password">Password</label>
                            <input type="password" id="password" name="password" placeholder="Inserisci la password" required>
                        </div>
                        <!-- Link alla pagina di registrazione -->
                        <p class="register-hint">Non sei ancora registrato? <a href="register.php">Registrati</a></p>
                        <button type="submit" name="Invia" class="btn-login">ACCEDI</button>
                    </form>
                </div>
                
                <script>
                    // Mostra il toast dopo 50ms e lo nasconde dopo 3 secondi
                    var t = document.getElementById('toast');
                    setTimeout(function(){ t.classList.add('show'); }, 50);
                    setTimeout(function(){ t.classList.remove('show'); }, 3000);
                </script>
                <?php
            }
        }
    ?>
</body>
</html>
