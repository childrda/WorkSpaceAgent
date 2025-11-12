# Database Schema Update Instructions

This guide explains how to update your existing database to add the `login_success` column to the `user_logins` table.

## Prerequisites

- MySQL/MariaDB is installed and running
- You have access to the database (either as root or the `mcp_agent` user)
- You know your MySQL password

## Method 1: Using the Migration Script (Recommended)

### Step 1: Navigate to the Project Directory

```bash
cd /opt/mcp_agent
# Or wherever you installed the agent
```

### Step 2: Run the Migration Script

**If you're using the `mcp_agent` MySQL user:**
```bash
mysql -u mcp_agent -p mcp_logs < migration_add_login_success.sql
```

**If you're using the `root` MySQL user:**
```bash
mysql -u root -p mcp_logs < migration_add_login_success.sql
```

You will be prompted to enter your MySQL password.

### Step 2 (Optional): Create the drive_events table

If you want to enable the debugging flag that stores every Google Drive event, add the new `drive_events` table:

```bash
mysql -u mcp_agent -p mcp_logs -e "
CREATE TABLE IF NOT EXISTS drive_events (
  id BIGINT AUTO_INCREMENT PRIMARY KEY,
  actor_email VARCHAR(255),
  owner_domain VARCHAR(255),
  owner_display_name VARCHAR(255),
  doc_id VARCHAR(128),
  doc_title TEXT,
  visibility VARCHAR(128),
  event_type VARCHAR(128),
  raw_event JSON,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  INDEX idx_actor_email (actor_email),
  INDEX idx_created_at (created_at)
);
"
```

If you prefer SQL files, just rerun `schema.sql` and the table will be created automatically.

### Step 3 (Optional): Create the phishing_emails table

If you plan to enable Gmail phishing detection, add the `phishing_emails` table to capture suspicious messages:

```bash
mysql -u mcp_agent -p mcp_logs -e "
CREATE TABLE IF NOT EXISTS phishing_emails (
  id BIGINT AUTO_INCREMENT PRIMARY KEY,
  message_id VARCHAR(255) UNIQUE,
  subject VARCHAR(255),
  sender_email VARCHAR(255),
  sender_display VARCHAR(255),
  sender_domain VARCHAR(255),
  recipients TEXT,
  suspicious_reasons JSON,
  share_links JSON,
  auth_results TEXT,
  snippet TEXT,
  message_time DATETIME,
  ai_label VARCHAR(64),
  ai_confidence FLOAT,
  rule_score INT,
  phishing_confidence FLOAT,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  INDEX idx_sender_email (sender_email),
  INDEX idx_message_time (message_time)
);
"
```

Again, rerunning `schema.sql` will create both optional tables automatically.

### Step 4: Verify the Update

Connect to MySQL and check the table structure:
```bash
mysql -u mcp_agent -p mcp_logs
```

Then run:
```sql
DESCRIBE user_logins;
```

You should see `login_success` listed as a column with type `tinyint(1)` (which is MySQL's BOOLEAN type).

Exit MySQL:
```sql
EXIT;
```

## Method 2: Manual SQL Commands

If you prefer to run the SQL commands manually:

### Step 1: Connect to MySQL

```bash
mysql -u mcp_agent -p mcp_logs
# Or: mysql -u root -p mcp_logs
```

### Step 2: Run the SQL Commands

```sql
-- Add the login_success column
ALTER TABLE user_logins 
ADD COLUMN login_success BOOLEAN DEFAULT TRUE;

-- Update existing records (set all to TRUE/successful)
UPDATE user_logins 
SET login_success = TRUE 
WHERE login_success IS NULL;
```

### Step 3: Verify

```sql
DESCRIBE user_logins;
EXIT;
```

## Troubleshooting

### Error: "Duplicate column name 'login_success'"

**Meaning:** The column already exists. Your database is already up to date!

**Solution:** No action needed. You can safely ignore this error.

### Error: "Access denied"

**Meaning:** Your MySQL user doesn't have permission to alter the table.

**Solutions:**
1. Use the root user instead:
   ```bash
   mysql -u root -p mcp_logs < migration_add_login_success.sql
   ```

2. Or grant ALTER permissions to your user:
   ```sql
   -- As root:
   GRANT ALTER ON mcp_logs.* TO 'mcp_agent'@'localhost';
   FLUSH PRIVILEGES;
   ```

### Error: "Unknown database 'mcp_logs'"

**Meaning:** The database doesn't exist yet.

**Solution:** Create the database first:
```bash
mysql -u root -p
```

Then:
```sql
CREATE DATABASE mcp_logs;
EXIT;
```

Then run the full schema setup:
```bash
mysql -u root -p mcp_logs < schema.sql
```

### Error: "Table 'user_logins' doesn't exist"

**Meaning:** The table hasn't been created yet.

**Solution:** Run the full schema setup first:
```bash
mysql -u root -p mcp_logs < schema.sql
```

## What This Update Does

- **Adds a new column** `login_success` to the `user_logins` table
- **Optionally adds** a `drive_events` table for storing raw Drive audit events when debugging
- **Optionally adds** a `phishing_emails` table so Gmail phishing detections (with AI metadata) can be stored and reviewed
- **Sets default value** to `TRUE` (meaning successful logins)
- **Updates existing records** to mark them all as successful (since we don't have historical success/failure data)
- **Future logins** will be properly marked as successful or failed based on the Google Workspace event data

## After the Update

1. **Restart the agent** (if it's running):
   ```bash
   sudo systemctl restart mcp_agent
   # Or if running manually, stop and restart it
   ```

2. **Check the dashboard** - you should now see:
   - Full timestamps (date and time) in the login attempts table
   - A "Status" column showing "Success" or "Failed" for each login

## Verification Checklist

- [ ] Migration script ran without errors (or got "duplicate column" error, which is fine)
- [ ] `DESCRIBE user_logins;` shows the `login_success` column
- [ ] Agent restarted successfully
- [ ] Dashboard shows timestamps with time (not just date)
- [ ] Dashboard shows Status column with Success/Failed indicators

