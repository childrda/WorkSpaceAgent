import os
import json
import time
from datetime import datetime, timedelta
from dotenv import load_dotenv
from google.oauth2 import service_account
from googleapiclient.discovery import build

from alert_utils import send_email_alert, fetch_security_alerts
from login_processor import process_login_event
from drive_processor import process_drive_event

# Load environment and config
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
load_dotenv(os.path.join(BASE_DIR, '.env'))
with open(os.path.join(BASE_DIR, 'config.json')) as f:
    CONFIG = json.load(f)

SERVICE_ACCOUNT_FILE = os.getenv('SERVICE_ACCOUNT_FILE')
SCOPES = os.getenv('GOOGLE_SCOPES').split(',')
ADMIN_EMAIL = CONFIG['google']['admin_email']
POLL_INTERVAL = int(CONFIG['poll_interval_minutes']) * 60

credentials = service_account.Credentials.from_service_account_file(
    SERVICE_ACCOUNT_FILE, scopes=SCOPES
)
delegated_creds = credentials.with_subject(ADMIN_EMAIL)
reports_service = build('admin', 'reports_v1', credentials=delegated_creds)
alerts_service = build('alertcenter', 'v1beta1', credentials=delegated_creds)

def main_loop():
    print(f"[+] MCP Workspace Agent started for {CONFIG['domain']}")
    print(f"[+] Polling every {POLL_INTERVAL/60:.0f} minutes...")
    last = datetime.utcnow() - timedelta(seconds=POLL_INTERVAL)

    while True:
        start_time = last.isoformat() + 'Z'
        now = datetime.utcnow()
        try:
            print(f"[DEBUG] Querying events from {start_time} to {now.isoformat()}Z")
            
            # Fetch Google security alerts
            sec_alerts = fetch_security_alerts(alerts_service, CONFIG)
            print(f"[DEBUG] Security alerts found: {len(sec_alerts)}")
            # Create a dict mapping user email to alert info for easier lookup
            sec_alerts_dict = {a['user']: a for a in sec_alerts if a.get('user')}

            # Get login events
            login_response = reports_service.activities().list(
                userKey='all', applicationName='login', startTime=start_time
            ).execute()
            
            # Debug: Print how many events were returned
            logins = login_response.get('items', [])
            print(f"[DEBUG] Login events: {len(logins)}")
            if logins:
                print(f"[DEBUG] First login event sample:")
                print(json.dumps(logins[0], indent=2))
            
            for item in logins:
                process_login_event(item, sec_alerts_dict, CONFIG)

            # Get Drive events
            drive_response = reports_service.activities().list(
                userKey='all', applicationName='drive', startTime=start_time
            ).execute()
            
            # Debug: Print how many events were returned
            drives = drive_response.get('items', [])
            print(f"[DEBUG] Drive events: {len(drives)}")
            if drives:
                print(f"[DEBUG] First drive event sample:")
                print(json.dumps(drives[0], indent=2))
            
            for item in drives:
                process_drive_event(item, CONFIG)

        except Exception as e:
            print(f"[!] API error: {e}")

        last = now
        time.sleep(POLL_INTERVAL)

if __name__ == '__main__':
    main_loop()
