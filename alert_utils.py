import os
import smtplib
import json
from email.mime.text import MIMEText


def _get_smtp_port():
    port_value = (os.getenv('SMTP_PORT') or '').strip()
    if not port_value:
        return 587
    try:
        return int(port_value)
    except ValueError:
        print(f"[!] Invalid SMTP_PORT value '{port_value}'. Falling back to 587.")
        return 587


def send_email_alert(subject, message, config=None):
    """
    Send an email alert to the address defined in .env (ALERT_EMAIL).
    """
    if config and not config.get('alerts', {}).get('enable_email', True):
        return False

    SMTP_SERVER = os.getenv('SMTP_SERVER')
    SMTP_PORT = _get_smtp_port()
    SMTP_USERNAME = os.getenv('SMTP_USERNAME')
    SMTP_PASSWORD = os.getenv('SMTP_PASSWORD')
    ALERT_EMAIL = os.getenv('ALERT_EMAIL')

    missing_fields = [
        name for name, value in {
            'SMTP_SERVER': SMTP_SERVER,
            'SMTP_USERNAME': SMTP_USERNAME,
            'SMTP_PASSWORD': SMTP_PASSWORD,
            'ALERT_EMAIL': ALERT_EMAIL,
        }.items() if not value
    ]

    if missing_fields:
        print(f"[!] Email alert not sent. Missing SMTP configuration values: {', '.join(missing_fields)}")
        return False

    try:
        msg = MIMEText(message)
        msg['From'] = SMTP_USERNAME
        msg['To'] = ALERT_EMAIL
        msg['Subject'] = subject

        with smtplib.SMTP(SMTP_SERVER, SMTP_PORT) as server:
            server.starttls()
            server.login(SMTP_USERNAME, SMTP_PASSWORD)
            server.send_message(msg)

        print(f"[+] Email alert sent: {subject}")
        return True
    except Exception as e:
        print(f"[!] Failed to send email: {e}")
        return False


def fetch_security_alerts(alerts_service, CONFIG):
    """
    Retrieve recent security alerts (new device logins, suspicious logins)
    from Google Workspace Alert Center.
    Returns list of alerts with user email, title, and type.
    """
    alerts = []
    if not CONFIG['google'].get('use_alert_center', True):
        return alerts

    try:
        result = alerts_service.alerts().list(
            pageSize=CONFIG['google'].get('max_alerts', 50)
        ).execute()

        for alert in result.get('alerts', []):
            title = alert.get('title', '')
            alert_type = alert.get('type', '')
            
            # Check for new device or suspicious login alerts
            is_new_device = ('New device' in title or 
                           'new device' in title.lower() or
                           'Suspicious login' in title or
                           'suspicious login' in title.lower() or
                           'login' in alert_type.lower())
            
            if is_new_device:
                # Extract user email from alert data
                user_email = None
                alert_data = alert.get('data', {})
                
                # Try different paths to extract user email
                if isinstance(alert_data, dict):
                    # Check common fields where user email might be
                    user_email = (alert_data.get('userEmail') or 
                                alert_data.get('email') or
                                alert_data.get('actor', {}).get('email') or
                                alert_data.get('user', {}).get('email'))
                
                # If not found in data, check metadata
                if not user_email:
                    metadata = alert.get('metadata', {})
                    if isinstance(metadata, dict):
                        user_email = (metadata.get('userEmail') or 
                                    metadata.get('email') or
                                    metadata.get('actor', {}).get('email'))
                
                # If still not found, try to extract from alert ID or other fields
                if not user_email:
                    # Some alerts have user info in the source field
                    source = alert.get('source', '')
                    if '@' in str(source):
                        user_email = source
                
                if user_email:
                    alerts.append({
                        'user': user_email,
                        'title': title,
                        'type': alert_type,
                        'createTime': alert.get('createTime'),
                        'alertId': alert.get('alertId'),
                        'is_new_device': 'new device' in title.lower()
                    })
                else:
                    # Log alert even if we can't extract user for debugging
                    print(f"[!] Could not extract user from alert: {title} (ID: {alert.get('alertId')})")
                    
    except Exception as e:
        print(f"[!] Failed to fetch alerts: {e}")

    return alerts
