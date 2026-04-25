-- Schema del database NetVision
-- Eseguire questo file in phpMyAdmin o tramite MySQL CLI

CREATE DATABASE IF NOT EXISTS NetVision
    CHARACTER SET utf8mb4
    COLLATE utf8mb4_general_ci;

USE NetVision;

-- Tabella utenti
CREATE TABLE IF NOT EXISTS users (
    id       INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(100) NOT NULL UNIQUE,
    password VARCHAR(255) NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- Tabella dispositivi di rete
CREATE TABLE IF NOT EXISTS devices (
    id         INT AUTO_INCREMENT PRIMARY KEY,
    name       VARCHAR(100) NOT NULL,
    ip         VARCHAR(45)  NOT NULL,
    type       VARCHAR(50)  NOT NULL DEFAULT 'pc',
    status     ENUM('online','offline','unknown') NOT NULL DEFAULT 'unknown',
    last_check DATETIME DEFAULT NULL,
    ping_ms    INT DEFAULT NULL,
    notes      TEXT DEFAULT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
