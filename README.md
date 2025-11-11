# Google Workspace Security Monitoring Agent

A Python-based security monitoring agent that continuously monitors Google Workspace logs for security threats including impossible travel logins, new device sign-ons, and phishing attempts.

## Features

### 🔐 Security Alert Monitoring
- **Impossible Travel Detection**: Detects logins from geographically distant locations within short time frames (500+ mph threshold)
- **New Device Sign-on Alerts**: Cross-references Google Alert Center security alerts with login locations
- **State-Based Filtering**: Alerts when new device logins occur outside of Virginia (VA) state
- **Location Tracking**: Maintains historical login location data in database for cross-referencing

### 🎣 Phishing Detection
- **Public Sharing Detection**: Identifies documents shared with "anyone with the link" visibility
- **Impersonation Detection**: Flags attempts to impersonate leadership roles (superintendent, principal, etc.)
- **External User Monitoring**: Tracks suspicious activity from external domains
- **Combined Risk Analysis**: Detects high-risk combinations of public sharing and impersonation
- **Inbound Email Scanning (Gmail)**: Parses recent messages to flag suspicious links, spoofed leadership emails, urgency/financial language, and authentication failures

### 📊 Data Storage
- MySQL database for persistent storage of:
  - User login events with geolocation data
  - Security alerts
  - Phishing alerts
- In-memory caching for performance optimization

## Requirements

- Linux operating system (Ubuntu, Debian, CentOS, RHEL, etc.)
- Python 3.7+
- MySQL 5.7+ or MariaDB 10.3+
- Gmail API access (read-only)
- MaxMind GeoLite2 City database
- Google Service Account with appropriate permissions

## Prerequisites

Before installing the agent, you need to set up your Linux system with the required software.

### Step 1: Update Your Linux System

**For Ubuntu/Debian:**
```bash
sudo apt update
sudo apt upgrade -y
```

**For CentOS/RHEL/Rocky Linux:**
```bash
sudo yum update -y
# Or for newer versions:
sudo dnf update -y
```

### Step 2: Install Python 3 and pip

**For Ubuntu/Debian:**
```bash
sudo apt install -y python3 python3-pip python3-venv
# Verify installation
python3 --version
pip3 --version
```

**For CentOS/RHEL/Rocky Linux:**
```bash
sudo yum install -y python3 python3-pip
# Or for newer versions:
sudo dnf install -y python3 python3-pip
# Verify installation
python3 --version
pip3 --version
```

### Step 3: Install MySQL

**For Ubuntu/Debian:**
```bash
sudo apt install -y mysql-server
# Start MySQL service
sudo systemctl start mysql
sudo systemctl enable mysql
# Secure MySQL installation (follow prompts)
sudo mysql_secure_installation
```

**For CentOS/RHEL/Rocky Linux:**
```bash
sudo yum install -y mysql-server
# Or for newer versions:
sudo dnf install -y mysql-server
# Start MySQL service
sudo systemctl start mysqld
sudo systemctl enable mysqld
# Get temporary root password (if first install)
sudo grep 'temporary password' /var/log/mysqld.log
# Secure MySQL installation
sudo mysql_secure_installation
```

**Create Database and User:**
```bash
# Log into MySQL as root
sudo mysql -u root -p

# In MySQL prompt, run:
CREATE DATABASE mcp_logs;
CREATE USER 'mcp_agent'@'localhost' IDENTIFIED BY 'YourStrongMySQLPassword';
GRANT ALL PRIVILEGES ON mcp_logs.* TO 'mcp_agent'@'localhost';
FLUSH PRIVILEGES;
EXIT;
```

**Note:** Replace `YourStrongMySQLPassword` with a strong password of your choice. You'll need this password for the `.env` file later.

### Step 4: Install Git (if not already installed)

**For Ubuntu/Debian:**
```bash
sudo apt install -y git
```

**For CentOS/RHEL/Rocky Linux:**
```bash
sudo yum install -y git
# Or for newer versions:
sudo dnf install -y git
```

## Installation

1. **Clone the repository**
   ```bash
   # Clone to current directory (creates WorkSpaceAgent folder)
   git clone https://github.com/childrda/WorkSpaceAgent.git
   cd WorkSpaceAgent
   
   # Or clone to a specific location
   git clone https://github.com/childrda/WorkSpaceAgent.git /path/to/destination
   cd /path/to/destination/WorkSpaceAgent
   ```

2. **Choose installation location** (optional)
   
   The default configuration assumes files are in `/opt/mcp_agent/` (Linux production path). You can:
   
   **Option A: Move repository to `/opt/mcp_agent/` (recommended for Linux production)**
   ```bash
   sudo mkdir -p /opt/mcp_agent
   sudo cp -r WorkSpaceAgent/* /opt/mcp_agent/
   cd /opt/mcp_agent
   ```
   
   **Option B: Keep repository in current location**
   - Update paths in `config.json` and `.env` to match your chosen location
   - Example: If keeping in `~/WorkSpaceAgent`, update:
     - `geo_db_path` in `config.json`
     - `archive_path` in `config.json`
     - `SERVICE_ACCOUNT_FILE` in `.env`
   
   **Option C: Use any custom location**
   - Update all file paths in `config.json` and `.env` to match your location

3. **Create and activate virtual environment** (recommended)
   
   Navigate to your installation directory (e.g., `/opt/mcp_agent`):
   ```bash
   cd /opt/mcp_agent
   
   # Create virtual environment
   python3 -m venv venv
   
   # Activate virtual environment
   source venv/bin/activate
   
   # Upgrade pip
   pip install --upgrade pip
   ```

4. **Install Python dependencies**
   
   With the virtual environment activated:
   ```bash
   # Install all required packages (agent and dashboard share the same requirements)
   pip install -r requirements.txt
   ```
   
   **Note:** If you prefer not to use a virtual environment, you can install directly:
   ```bash
   pip3 install -r requirements.txt
   # Or if pip3 is not found:
   python3 -m pip install -r requirements.txt
   ```

5. **Set up database schema**
   
   If you haven't already created the database (see Prerequisites Step 3), do that first, then:
   ```bash
   mysql -u mcp_agent -p mcp_logs < schema.sql
   ```
   
   **Note:** Use the password you created for the `mcp_agent` MySQL user. If you used root instead, use:
   ```bash
   mysql -u root -p mcp_logs < schema.sql
   ```
   
   **For existing installations:** If you already have a database set up and need to update the schema (e.g., to add the `login_success` column), see `SCHEMA_UPDATE.md` for detailed migration instructions.

6. **Download MaxMind GeoLite2 City database**
   - Sign up for a free account at [MaxMind](https://www.maxmind.com/en/geolite2/signup)
   - Download the GeoLite2-City.mmdb file
   - Place it in your desired location (default: `/opt/mcp_agent/GeoLite2-City.mmdb`)

7. **Configure Google Workspace Service Account**
   - Create a service account in Google Cloud Console
   - Enable the following APIs:
     - Admin SDK API
     - Alert Center API
   - Grant the service account domain-wide delegation
   - Download the service account JSON key file
   - Place it in your installation directory (default: `/opt/mcp_agent/service_account.json`)

8. **Set up environment variables**
   ```bash
   cp example.env .env
   # Edit .env with your configuration
   ```

9. **Configure application settings**
   ```bash
   cp config.json.example config.json
   # Edit config.json with your domain and settings
   ```

## Configuration

### Environment Variables (.env)

```env
# Google Workspace Service Account
SERVICE_ACCOUNT_FILE=/path/to/service_account.json
GOOGLE_SCOPES=https://www.googleapis.com/auth/admin.reports.audit.readonly,https://www.googleapis.com/auth/apps.alerts

# Email Alerts (SMTP)
ALERT_EMAIL=alerts@yourdomain.com
SMTP_SERVER=smtp.office365.com
SMTP_PORT=587
SMTP_USERNAME=alerts@yourdomain.com
SMTP_PASSWORD=YourPassword

# MySQL Database
MYSQL_HOST=localhost
MYSQL_PORT=3306
MYSQL_USER=mcp_agent
MYSQL_PASSWORD=YourMySQLPassword
MYSQL_DB=mcp_logs
```

### Configuration File (config.json)

```json
{
  "poll_interval_minutes": 5,
  "geo_db_path": "/opt/mcp_agent/GeoLite2-City.mmdb",
  "domain": "yourdomain.com",
  "log_level": "INFO",
  "google": {
    "admin_email": "admin@yourdomain.com",
    "use_alert_center": true,
    "max_alerts": 50
  },
  "alerts": {
    "enable_email": true,
    "alert_subject_prefix": "[SECURITY ALERT]"
  }
}
```

-If you need additional sections, copy `config.json.example` and update as needed.
To inspect every Drive event for troubleshooting, set "log_all_drive_events": true inside the phishing block (see config.json.example). Remember to create the drive_events table or rerun schema.sql first.
You can also disable Drive processing entirely by setting `"drive": { "enabled": false }` if you only want Gmail scanning.

For Gmail scanning, add the `gmail` block from `config.json.example`, set `mailbox` to the delegated inbox you want to monitor, and make sure Gmail API read access is enabled for your service account.

## Usage

### Running the Agent

**If using virtual environment:**
```bash
cd /opt/mcp_agent
source venv/bin/activate
python workspace_agent.py
```

**If not using virtual environment:**
```bash
cd /opt/mcp_agent
python3 workspace_agent.py
```

The agent will:
1. Poll Google Workspace logs every 5 minutes (configurable)
2. Check for security alerts from Google Alert Center
3. Process login events for impossible travel detection
4. Process Drive events for phishing detection
5. Send email alerts for security incidents

**Running as a background service:**
```bash
# Using nohup (simple method)
cd /opt/mcp_agent
source venv/bin/activate
nohup python workspace_agent.py > agent.log 2>&1 &

# Or using systemd (recommended for production)
# Create /etc/systemd/system/mcp-agent.service (see below)
sudo systemctl start mcp-agent
sudo systemctl enable mcp-agent
```

**Systemd service file example** (`/etc/systemd/system/mcp-agent.service`):
```ini
[Unit]
Description=Google Workspace Security Monitoring Agent
After=network.target mysql.service

[Service]
Type=simple
User=your-username
WorkingDirectory=/opt/mcp_agent
Environment="PATH=/opt/mcp_agent/venv/bin"
ExecStart=/opt/mcp_agent/venv/bin/python /opt/mcp_agent/workspace_agent.py
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
```

### Log Retention and Archiving

The agent includes automatic log retention and archiving functionality. Configure retention settings in `config.json`:

```json
"retention": {
  "retention_days": 180,
  "archive_path": "/opt/mcp_agent/archives",
  "enable_archiving": true
}
```

**Pruning Process:**
- Run `prune_logs.py` daily to remove logs older than the retention period
- Before deletion, an SQL dump archive is created automatically
- Archives are stored in the configured `archive_path` directory

**Setting up Daily Pruning:**

**Linux (cron):**
```bash
# Add to crontab (runs daily at 2 AM)
# If using virtual environment:
0 2 * * * cd /opt/mcp_agent && /opt/mcp_agent/venv/bin/python /opt/mcp_agent/prune_logs.py >> /var/log/mcp_agent_prune.log 2>&1

# If not using virtual environment:
0 2 * * * /usr/bin/python3 /opt/mcp_agent/prune_logs.py >> /var/log/mcp_agent_prune.log 2>&1
```

**Windows (Task Scheduler):**
1. Open Task Scheduler
2. Create Basic Task
3. Set trigger to Daily at 2:00 AM
4. Action: Start a program
5. Program: `python`
6. Arguments: `D:\WorkSpaceAgent\prune_logs.py`
7. Start in: `D:\WorkSpaceAgent`

**Manual Pruning:**
```bash
python prune_logs.py
```

The script will:
- Create an SQL archive dump of data to be deleted
- Remove logs older than the retention period
- Report the number of records pruned from each table

## Google Workspace API Permissions

The service account requires the following OAuth scopes:
- `https://www.googleapis.com/auth/admin.reports.audit.readonly` - Read audit logs
- `https://www.googleapis.com/auth/apps.alerts` - Access Alert Center
- `https://www.googleapis.com/auth/gmail.readonly` - Read Gmail messages for phishing detection

The service account must have domain-wide delegation enabled and be granted access to:
- Admin SDK (Reports API)
- Alert Center API
- Gmail API (read-only)

## Database Schema

The agent uses three main tables:

- **user_logins**: Stores login events with geolocation data
- **security_alerts**: Stores security alerts (impossible travel, new device, etc.)
- **phishing_alerts**: Stores phishing and impersonation alerts from Drive
- **drive_events** *(optional)*: Raw Google Drive events when `log_all_drive_events` is enabled
- **phishing_emails** *(optional)*: Suspicious Gmail messages detected by the phishing scanner

### Gmail Phishing Detection (Optional)

1. **Enable Gmail API** for your service account and add the `https://www.googleapis.com/auth/gmail.readonly` scope to `GOOGLE_SCOPES` in `.env`.
2. **Grant domain-wide delegation** for the Gmail API to the service account and ensure the delegated mailbox (configured in `config.json`) has read access to the messages you want to monitor.
3. **Create the optional database tables** by rerunning `schema.sql` (or manually creating `drive_events` and `phishing_emails` as documented in `SCHEMA_UPDATE.md`).
4. **Update `config.json`** with the `gmail` block (see `config.json.example`) and set:
   - `mailbox`: the delegated mailbox to scan (e.g., `security-alerts@yourdomain.com`)
   - `allowed_sender_domains`: trusted internal domains (messages from these domains are not flagged by impersonation rules unless other red flags appear)
   - `trusted_file_domains`: file-sharing domains you trust (e.g., `yourdomain.com`)
   - `high_risk_display_names`: names/roles you want to monitor for spoofing (superintendent, CFO, principal, etc.)
   - `urgency_keywords`, `financial_keywords`: phrases that indicate urgency or financial lures (gift cards, payroll, wire transfer)
5. **Restart the agent** so the new configuration and scope take effect.

The agent stores suspicious Gmail messages in the `phishing_emails` table and issues email alerts (if enabled) summarising the reasons (external share links, spoofed display names, SPF/DKIM/DMARC failures, etc.).