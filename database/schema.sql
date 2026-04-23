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
    last_check DATETIME DEFAULT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- Storico dei controlli e dei cambi stato
CREATE TABLE IF NOT EXISTS device_status_history (
    id               INT AUTO_INCREMENT PRIMARY KEY,
    device_id        INT NOT NULL,
    previous_status  ENUM('online','offline','unknown') DEFAULT NULL,
    current_status   ENUM('online','offline','unknown') NOT NULL,
    changed          TINYINT(1) NOT NULL DEFAULT 0,
    source           VARCHAR(50) NOT NULL DEFAULT 'manual-check',
    response_time_ms INT DEFAULT NULL,
    checked_at       DATETIME NOT NULL,
    INDEX idx_device_checked_at (device_id, checked_at),
    CONSTRAINT fk_device_status_history_device
        FOREIGN KEY (device_id) REFERENCES devices(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- Alert e notifiche interne alla dashboard
CREATE TABLE IF NOT EXISTS device_alerts (
    id         INT AUTO_INCREMENT PRIMARY KEY,
    device_id  INT DEFAULT NULL,
    category   VARCHAR(50) NOT NULL,
    title      VARCHAR(150) NOT NULL,
    message    TEXT NOT NULL,
    created_at DATETIME NOT NULL,
    INDEX idx_alerts_created_at (created_at),
    CONSTRAINT fk_device_alerts_device
        FOREIGN KEY (device_id) REFERENCES devices(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
