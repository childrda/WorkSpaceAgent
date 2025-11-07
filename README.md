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

- Python 3.7+
- MySQL 5.7+ or MariaDB 10.3+
- Google Workspace Admin API access
- MaxMind GeoLite2 City database
- Google Service Account with appropriate permissions

## Installation

1. **Clone the repository**
   ```bash
   git clone <repository-url>
   cd WorkSpaceAgent
   ```

2. **Install Python dependencies**
   ```bash
   pip install -r requirements.txt
   ```

3. **Set up MySQL database**
   ```bash
   mysql -u root -p < schema.sql
   ```

4. **Download MaxMind GeoLite2 City database**
   - Sign up for a free account at [MaxMind](https://www.maxmind.com/en/geolite2/signup)
   - Download the GeoLite2-City.mmdb file
   - Place it in your desired location (default: `/opt/mcp_agent/GeoLite2-City.mmdb`)

5. **Configure Google Workspace Service Account**
   - Create a service account in Google Cloud Console
   - Enable the following APIs:
     - Admin SDK API
     - Alert Center API
   - Grant the service account domain-wide delegation
   - Download the service account JSON key file

6. **Set up environment variables**
   ```bash
   cp example.env .env
   # Edit .env with your configuration
   ```

7. **Configure application settings**
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

## File Structure

```
WorkSpaceAgent/
├── workspace_agent.py      # Main agent loop
├── login_processor.py      # Login event processing
├── drive_processor.py      # Drive event processing
├── alert_utils.py          # Alert fetching and email sending
├── db_helpers.py           # Database operations
├── geo_utils.py            # IP geolocation utilities
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

