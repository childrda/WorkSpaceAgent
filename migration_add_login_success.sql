-- Migration script to add login_success column to existing user_logins table
-- Run with: mysql -u root -p mcp_logs < migration_add_login_success.sql
-- 
-- Note: If the column already exists, you'll get an error. That's okay - just means it's already migrated.

-- Add login_success column (will error if already exists - that's fine)
ALTER TABLE user_logins 
ADD COLUMN login_success BOOLEAN DEFAULT TRUE;

-- Update existing records to default to TRUE (successful) if NULL
UPDATE user_logins 
SET login_success = TRUE 
WHERE login_success IS NULL;

