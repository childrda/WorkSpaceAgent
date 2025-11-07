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

### Step 3: Verify the Update

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

