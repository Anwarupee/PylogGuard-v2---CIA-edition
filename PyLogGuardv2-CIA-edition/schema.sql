DROP DATABASE IF EXISTS attack_logs_db;
CREATE DATABASE IF NOT EXISTS attack_logs_db;
USE attack_logs_db;

CREATE TABLE IF NOT EXISTS roles (
    role_id INT AUTO_INCREMENT PRIMARY KEY,
    role_name VARCHAR(50) NOT NULL UNIQUE,
    description TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_role_name (role_name)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- Default roles
INSERT IGNORE INTO roles (role_name, description) VALUES
('admin', 'Full system access'),
('analyst', 'View and analyze logs'),
('viewer', 'Read-only access'),
('operator', 'Monitor and respond to alerts');

-- ============================================================================
-- USERS TABLE
-- ============================================================================
CREATE TABLE IF NOT EXISTS users (
    user_id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(100) NOT NULL UNIQUE,
    email VARCHAR(255) NOT NULL UNIQUE,
    password_hash VARCHAR(255) NOT NULL,
    role_id INT NOT NULL,
    is_active BOOLEAN DEFAULT TRUE,
    last_login TIMESTAMP NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    FOREIGN KEY (role_id) REFERENCES roles(role_id) ON DELETE RESTRICT,
    INDEX idx_username (username),
    INDEX idx_email (email),
    INDEX idx_active (is_active)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- ============================================================================
-- LOG ENTRIES TABLE (Main CIA Logs)
-- ============================================================================
CREATE TABLE IF NOT EXISTS log_entries (
    log_id BIGINT AUTO_INCREMENT PRIMARY KEY,
    
    -- Temporal Information
    timestamp DATETIME NOT NULL,
    ingestion_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    
    -- Source Information
    source VARCHAR(50) NOT NULL,  -- snort, proxy, samba, syslog, wireshark
    source_ip VARCHAR(45),         -- IPv4 or IPv6
    destination_ip VARCHAR(45),
    
    -- Event Classification
    event_type VARCHAR(100) NOT NULL,      -- dos_attack, auth_failure, etc.
    cia_category VARCHAR(20) NOT NULL,     -- Confidentiality, Integrity, Availability
    severity VARCHAR(20) DEFAULT 'Low',    -- High, Medium, Low, Info
    
    -- Event Details (JSON for flexibility)
    raw_log TEXT,                          -- Original log line
    parsed_data JSON,                      -- Structured parsed data
    
    -- User Context
    username VARCHAR(100),                 -- If applicable
    user_id INT,                           -- Link to users table if internal
    
    -- Attack Metadata
    attack_signature VARCHAR(255),         -- Snort SID, detection rule
    resource_affected VARCHAR(500),        -- URL, file path, share name
    
    -- Status
    is_false_positive BOOLEAN DEFAULT FALSE,
    is_resolved BOOLEAN DEFAULT FALSE,
    resolution_notes TEXT,
    resolved_by INT,
    resolved_at TIMESTAMP NULL,
    
    -- Indexes for Performance
    INDEX idx_timestamp (timestamp),
    INDEX idx_source (source),
    INDEX idx_event_type (event_type),
    INDEX idx_cia_category (cia_category),
    INDEX idx_severity (severity),
    INDEX idx_source_ip (source_ip),
    INDEX idx_composite_search (timestamp, cia_category, source),
    INDEX idx_unresolved (is_resolved, severity),
    
    FOREIGN KEY (user_id) REFERENCES users(user_id) ON DELETE SET NULL,
    FOREIGN KEY (resolved_by) REFERENCES users(user_id) ON DELETE SET NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- ============================================================================
-- ATTACK PATTERNS TABLE (For Correlation & Detection)
-- ============================================================================
CREATE TABLE IF NOT EXISTS attack_patterns (
    pattern_id INT AUTO_INCREMENT PRIMARY KEY,
    attack_type VARCHAR(100) NOT NULL,     -- bruteforce, dos, port_scan
    source_ip VARCHAR(45) NOT NULL,
    first_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    event_count INT DEFAULT 1,
    cia_category VARCHAR(20),
    severity VARCHAR(20) DEFAULT 'Medium',
    is_active BOOLEAN DEFAULT TRUE,
    notes TEXT,
    
    INDEX idx_attack_type (attack_type),
    INDEX idx_source_ip (source_ip),
    INDEX idx_active (is_active),
    INDEX idx_severity (severity),
    INDEX idx_first_seen (first_seen)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- ============================================================================
-- STATISTICS TABLE (Pre-computed for Dashboard)
-- ============================================================================
CREATE TABLE IF NOT EXISTS daily_statistics (
    stat_id INT AUTO_INCREMENT PRIMARY KEY,
    stat_date DATE NOT NULL,
    source VARCHAR(50),
    cia_category VARCHAR(20),
    event_count INT DEFAULT 0,
    unique_ips INT DEFAULT 0,
    high_severity_count INT DEFAULT 0,
    computed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    
    UNIQUE KEY uk_daily_stat (stat_date, source, cia_category),
    INDEX idx_stat_date (stat_date)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- ============================================================================
-- ALERTS TABLE (For Real-time Notifications)
-- ============================================================================
CREATE TABLE IF NOT EXISTS alerts (
    alert_id BIGINT AUTO_INCREMENT PRIMARY KEY,
    alert_type VARCHAR(100) NOT NULL,      -- bruteforce_detected, dos_attack, etc.
    severity VARCHAR(20) NOT NULL,
    source_ip VARCHAR(45),
    cia_category VARCHAR(20),
    description TEXT NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    is_acknowledged BOOLEAN DEFAULT FALSE,
    acknowledged_by INT,
    acknowledged_at TIMESTAMP NULL,
    
    INDEX idx_created_at (created_at),
    INDEX idx_unacknowledged (is_acknowledged),
    INDEX idx_severity (severity),
    FOREIGN KEY (acknowledged_by) REFERENCES users(user_id) ON DELETE SET NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- ============================================================================
-- AUDIT LOG TABLE (Track System Changes)
-- ============================================================================
CREATE TABLE IF NOT EXISTS audit_log (
    audit_id BIGINT AUTO_INCREMENT PRIMARY KEY,
    user_id INT,
    action VARCHAR(100) NOT NULL,          -- login, logout, update_log, delete_log
    target_type VARCHAR(50),               -- log_entry, user, role
    target_id BIGINT,
    old_value JSON,
    new_value JSON,
    ip_address VARCHAR(45),
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    
    INDEX idx_user_id (user_id),
    INDEX idx_timestamp (timestamp),
    INDEX idx_action (action),
    FOREIGN KEY (user_id) REFERENCES users(user_id) ON DELETE SET NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- ============================================================================
-- VIEWS FOR COMMON QUERIES
-- ============================================================================
--@block
-- View: Recent High-Severity Events
CREATE OR REPLACE VIEW v_high_severity_events AS
SELECT 
    log_id,
    timestamp,
    source,
    event_type,
    cia_category,
    source_ip,
    destination_ip,
    username
FROM log_entries
WHERE severity = 'High'
  AND is_false_positive = FALSE
  AND is_resolved = FALSE
ORDER BY timestamp DESC;
--@block
-- View: CIA Distribution Summary
CREATE OR REPLACE VIEW v_cia_summary AS
SELECT 
    cia_category,
    COUNT(*) as event_count,
    COUNT(DISTINCT source_ip) as unique_sources,
    SUM(CASE WHEN severity = 'High' THEN 1 ELSE 0 END) as high_severity,
    MIN(timestamp) as first_event,
    MAX(timestamp) as last_event
FROM log_entries
WHERE is_false_positive = FALSE
GROUP BY cia_category;
--@block
-- View: Top Attack Sources
CREATE OR REPLACE VIEW v_top_attackers AS
SELECT 
    source_ip,
    COUNT(*) as total_events,
    COUNT(DISTINCT event_type) as attack_types,
    MAX(severity) as max_severity,
    MAX(timestamp) as last_seen
FROM log_entries
WHERE cia_category IN ('Confidentiality', 'Integrity', 'Availability')
  AND is_false_positive = FALSE
GROUP BY source_ip
ORDER BY total_events DESC
LIMIT 50;

-- ============================================================================
-- STORED PROCEDURES
-- ============================================================================
--@block
DELIMITER //

-- Procedure: Insert Log Entry with Auto-pattern Detection
CREATE PROCEDURE sp_insert_log_entry(
    IN p_timestamp DATETIME,
    IN p_source VARCHAR(50),
    IN p_source_ip VARCHAR(45),
    IN p_destination_ip VARCHAR(45),
    IN p_event_type VARCHAR(100),
    IN p_cia_category VARCHAR(20),
    IN p_severity VARCHAR(20),
    IN p_raw_log TEXT,
    IN p_parsed_data JSON,
    IN p_username VARCHAR(100),
    IN p_resource VARCHAR(500)
)
BEGIN
    -- Insert the log entry
    INSERT INTO log_entries (
        timestamp, source, source_ip, destination_ip,
        event_type, cia_category, severity,
        raw_log, parsed_data, username, resource_affected
    ) VALUES (
        p_timestamp, p_source, p_source_ip, p_destination_ip,
        p_event_type, p_cia_category, p_severity,
        p_raw_log, p_parsed_data, p_username, p_resource
    );
    
    -- Update attack pattern if it's a threat
    IF p_cia_category IN ('Confidentiality', 'Integrity', 'Availability') THEN
        INSERT INTO attack_patterns (attack_type, source_ip, cia_category, severity, event_count)
        VALUES (p_event_type, p_source_ip, p_cia_category, p_severity, 1)
        ON DUPLICATE KEY UPDATE
            last_seen = CURRENT_TIMESTAMP,
            event_count = event_count + 1,
            severity = GREATEST(severity, p_severity);
    END IF;
END //

DELIMITER ;

-- ============================================================================
-- INDEXES OPTIMIZATION
-- ============================================================================
--@block
-- Composite index for dashboard queries
ALTER TABLE log_entries 
    ADD INDEX idx_dashboard_query (timestamp DESC, cia_category, severity);

-- Full-text search on raw logs (optional, for advanced search)
-- ALTER TABLE log_entries ADD FULLTEXT INDEX ft_raw_log (raw_log);

-- ============================================================================
-- SAMPLE DATA (Optional - for testing)
-- ============================================================================
--@block
-- Create test admin user (password: admin123 - CHANGE IN PRODUCTION!)
INSERT INTO users (username, email, password_hash, role_id) VALUES
('admin', 'admin@pylogguard.local', '$2b$12$LQv3c1yqBWVHxkd0LHAkCOYz6TtxMQJqhN8/LewY5GyYzpLaEg0dO', 1);