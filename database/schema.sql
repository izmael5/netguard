-- NetGuard database schema
CREATE DATABASE IF NOT EXISTS netguard CHARACTER SET utf8mb4;
USE netguard;

-- Targets you are authorized to scan (hostnames, IPs, CIDRs, URLs).
CREATE TABLE IF NOT EXISTS allowed_targets (
    id              INT AUTO_INCREMENT PRIMARY KEY,
    target          VARCHAR(255) NOT NULL UNIQUE,
    label           VARCHAR(255),
    target_type     ENUM('host','cidr','url') NOT NULL DEFAULT 'host',
    added_at        TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    notes           TEXT
);

-- One row per scan run
CREATE TABLE IF NOT EXISTS scans (
    id              INT AUTO_INCREMENT PRIMARY KEY,
    target          VARCHAR(255) NOT NULL,
    scan_type       ENUM('port','web','full') NOT NULL DEFAULT 'full',
    port_range      VARCHAR(50),
    status          ENUM('queued','running','completed','failed') DEFAULT 'queued',
    started_at      TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    finished_at     TIMESTAMP NULL,
    error_message   TEXT
);

-- Open ports / services found for a scan
CREATE TABLE IF NOT EXISTS scan_ports (
    id              INT AUTO_INCREMENT PRIMARY KEY,
    scan_id         INT NOT NULL,
    port            INT NOT NULL,
    protocol        VARCHAR(10) DEFAULT 'tcp',
    state           VARCHAR(20),
    service_name    VARCHAR(100),
    product         VARCHAR(150),
    version         VARCHAR(100),
    banner          VARCHAR(500),
    FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE
);

-- CVEs matched against detected product/version pairs
CREATE TABLE IF NOT EXISTS vulnerabilities (
    id              INT AUTO_INCREMENT PRIMARY KEY,
    scan_id         INT NOT NULL,
    scan_port_id    INT,
    cve_id          VARCHAR(30),
    severity        VARCHAR(20),
    cvss_score      DECIMAL(3,1),
    description     TEXT,
    reference_url   VARCHAR(500),
    FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE,
    FOREIGN KEY (scan_port_id) REFERENCES scan_ports(id) ON DELETE CASCADE
);

-- Web / HTTP-layer findings (headers, TLS, exposed paths, etc.)
CREATE TABLE IF NOT EXISTS web_findings (
    id              INT AUTO_INCREMENT PRIMARY KEY,
    scan_id         INT NOT NULL,
    category        VARCHAR(100),
    finding         VARCHAR(255),
    severity        VARCHAR(20),
    detail          TEXT,
    FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE
);

-- Generated report files
CREATE TABLE IF NOT EXISTS reports (
    id              INT AUTO_INCREMENT PRIMARY KEY,
    scan_id         INT NOT NULL,
    file_path       VARCHAR(500),
    format          VARCHAR(10) DEFAULT 'html',
    created_at      TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE
);

INSERT IGNORE INTO allowed_targets (target, label, target_type, notes)
VALUES ('127.0.0.1', 'localhost', 'host', 'Default safe target, edit/remove as needed.');
