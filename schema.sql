-- Google Workspace Security Monitoring Agent Database Schema
-- Run with: mysql -u root -p mcp_logs < schema.sql

CREATE TABLE IF NOT EXISTS user_logins (
  id BIGINT AUTO_INCREMENT PRIMARY KEY,
  email VARCHAR(255) NOT NULL,
  ip VARCHAR(45),
  latitude DOUBLE,
  longitude DOUBLE,
  country VARCHAR(100),
  region VARCHAR(100),
  city VARCHAR(100),
  asn VARCHAR(50),
  login_time DATETIME,
  login_success BOOLEAN DEFAULT TRUE,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  INDEX idx_email (email),
  INDEX idx_login_time (login_time)
);

CREATE TABLE IF NOT EXISTS phishing_alerts (
  id BIGINT AUTO_INCREMENT PRIMARY KEY,
  email VARCHAR(255),
  owner_domain VARCHAR(255),
  owner_display_name VARCHAR(255),
  file_id VARCHAR(128),
  file_title TEXT,
  file_link VARCHAR(512),
  visibility VARCHAR(128),
  visibility_change VARCHAR(255),
  reason VARCHAR(512),
  raw_event JSON,
  alerted BOOLEAN DEFAULT TRUE,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  INDEX idx_email (email),
  INDEX idx_owner_domain (owner_domain),
  INDEX idx_created_at (created_at)
);

CREATE TABLE IF NOT EXISTS security_alerts (
  id BIGINT AUTO_INCREMENT PRIMARY KEY,
  email VARCHAR(255),
  alert_type VARCHAR(100),
  details TEXT,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  INDEX idx_email (email),
  INDEX idx_created_at (created_at)
);
