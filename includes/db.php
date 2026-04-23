<?php
// Parametri di connessione al database
$ip     = 'localhost';
$user   = 'root';
$pwd    = '';
$dbname = 'NetVision';

// Connessione al database
$con = new mysqli($ip, $user, $pwd, $dbname);
