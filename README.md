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
- Google Workspace Admin API access
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

3. **Install Python dependencies**
   ```bash
   # Install required Python packages
   pip3 install -r requirements.txt
   
   # Or if pip3 is not found, try:
   python3 -m pip install -r requirements.txt
   ```
   
   **Optional: Use a virtual environment (recommended)**
   ```bash
   # Create virtual environment
   python3 -m venv venv
   
   # Activate virtual environment
   source venv/bin/activate
   
   # Install dependencies
   pip install -r requirements.txt
   ```

4. **Set up database schema**
   
   If you haven't already created the database (see Prerequisites Step 3), do that first, then:
   ```bash
   mysql -u mcp_agent -p mcp_logs < schema.sql
   ```
   
   **Note:** Use the password you created for the `mcp_agent` MySQL user. If you used root instead, use:
   ```bash
   mysql -u root -p mcp_logs < schema.sql
   ```

5. **Download MaxMind GeoLite2 City database**
   - Sign up for a free account at [MaxMind](https://www.maxmind.com/en/geolite2/signup)
   - Download the GeoLite2-City.mmdb file
   - Place it in your desired location (default: `/opt/mcp_agent/GeoLite2-City.mmdb`)

6. **Configure Google Workspace Service Account**
   - Create a service account in Google Cloud Console
   - Enable the following APIs:
     - Admin SDK API
     - Alert Center API
   - Grant the service account domain-wide delegation
   - Download the service account JSON key file
   - Place it in your installation directory (default: `/opt/mcp_agent/service_account.json`)

7. **Set up environment variables**
   ```bash
   cp example.env .env
   # Edit .env with your configuration
   ```

8. **Configure application settings**
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

## Usage

### Running the Agent

Run the agent:

```bash
python workspace_agent.py
```

The agent will:
1. Poll Google Workspace logs every 5 minutes (configurable)
2. Check for security alerts from Google Alert Center
3. Process login events for impossible travel detection
4. Process Drive events for phishing detection
5. Send email alerts for security incidents

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

The service account must have domain-wide delegation enabled and be granted access to:
- Admin SDK (Reports API)
- Alert Center API

## Database Schema

The agent uses three main tables:

- **user_logins**: Stores login events with geolocation data
- **security_alerts**: Stores security alerts (impossible travel, new device, etc.)
- **phishing_alerts**: Stores phishing and impersonation alerts

See `schema.sql` for the complete database schema.

## Alert Types

### Security Alerts
- `impossible_travel`: Login from distant location in short time
- `new_device_login`: New device login detected
- `new_device_outside_va`: New device login outside Virginia state

### Phishing Alerts
- Documents shared with "anyone with the link"
- Impersonation attempts (superintendent, principal, etc.)
- External users with suspicious sharing patterns

## Dashboard

The agent includes a web-based security dashboard for visualizing alerts and login activity.

### Running the Dashboard

1. **Install dashboard dependencies:**
   ```bash
   pip install -r requirements.txt
   ```

2. **Start the dashboard server:**
   ```bash
   python dashboard_api.py
   ```

3. **Access the dashboard:**
   Open your browser and navigate to: `http://localhost:5000`

The dashboard displays:
- **Top Metrics**: Login attempts, impossible travel alerts, security alerts, and phishing alerts
- **Impossible Travel Map**: Visual representation of impossible travel alerts with location markers
- **Login Attempts Table**: Recent login activity
- **Security Alerts by Type**: Bar chart showing alert breakdown
- **Phishing Alerts by Recipient**: Horizontal bar chart of phishing targets
- **Phishing Alerts Table**: Recent phishing attempts

The dashboard auto-refreshes every 30 seconds to show the latest data.

## File Structure

```
WorkSpaceAgent/
├── workspace_agent.py      # Main agent loop
├── login_processor.py      # Login event processing
├── drive_processor.py      # Drive event processing
├── alert_utils.py          # Alert fetching and email sending
├── db_helpers.py           # Database operations
├── geo_utils.py            # IP geolocation utilities
├── prune_logs.py          # Log retention and archiving script
├── dashboard_api.py        # Dashboard API server
├── dashboard/              # Dashboard frontend
│   └── index.html         # Dashboard HTML/CSS/JS
├── config.json             # Application configuration
├── schema.sql              # Database schema
├── requirements.txt        # Python dependencies
├── example.env             # Environment variable template
└── README.md              # This file
```

## Security Considerations

- Never commit `.env` or `service_account.json` to version control
- Store service account credentials securely
- Use strong passwords for database and SMTP accounts
- Regularly update the GeoLite2 database
- Monitor alert emails for false positives and adjust thresholds as needed

## Troubleshooting

### Common Issues

**Geo lookup fails**
- Ensure GeoLite2-City.mmdb file exists and path is correct
- Check file permissions

**Database connection errors**
- Verify MySQL is running
- Check database credentials in .env
- Ensure database and user exist

**Google API errors**
- Verify service account has correct permissions
- Check domain-wide delegation is enabled
- Ensure required APIs are enabled in Google Cloud Console

**No alerts received**
- Check SMTP configuration in .env
- Verify ALERT_EMAIL is correct
- Check spam folder

## License

This project is provided as-is for educational and security monitoring purposes.

## Contributing

Contributions are welcome! Please ensure:
- Code follows PEP 8 style guidelines
- New features include appropriate error handling
- Database migrations are included if schema changes are made

## Support

For issues and questions, please open an issue on the GitHub repository.

