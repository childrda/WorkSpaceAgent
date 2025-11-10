import os
import json
import time
from datetime import datetime, timedelta, timezone
from dotenv import load_dotenv
from google.oauth2 import service_account
from googleapiclient.discovery import build

from alert_utils import send_email_alert, fetch_security_alerts
from login_processor import process_login_event
from drive_processor import process_drive_event
from gmail_processor import process_gmail_messages

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
gmail_service = None
gmail_last_check = None

if CONFIG.get('gmail', {}).get('enabled'):
    gmail_service = build('gmail', 'v1', credentials=delegated_creds)
    lookback_minutes = CONFIG.get('gmail', {}).get('poll_lookback_minutes', 10)
    gmail_last_check = datetime.now(timezone.utc) - timedelta(minutes=lookback_minutes)


def main_loop():
    global gmail_last_check
    print(f"[+] MCP Workspace Agent started for {CONFIG['domain']}")
    print(f"[+] Polling every {POLL_INTERVAL/60:.0f} minutes...")
    last = datetime.now(timezone.utc) - timedelta(seconds=POLL_INTERVAL)

    while True:
        start_time = last.isoformat().replace('+00:00', 'Z')
        now = datetime.now(timezone.utc)
        now_str = now.isoformat().replace('+00:00', 'Z')
        try:
            print(f"[DEBUG] Querying events from {start_time} to {now_str}")

            if gmail_service:
                global gmail_last_check
                try:
                    scanned, flagged, gmail_last_check = process_gmail_messages(
                        gmail_service,
                        CONFIG,
                        gmail_last_check or (datetime.now(timezone.utc) - timedelta(minutes=CONFIG.get('gmail', {}).get('poll_lookback_minutes', 10)))
                    )
                    print(f"[DEBUG] Gmail messages scanned: {scanned}, flagged: {flagged}")
                except Exception as gmail_error:
                    print(f"[!] Gmail processing error: {gmail_error}")

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

            for item in reversed(logins):
                try:
                    process_login_event(item, sec_alerts_dict, CONFIG)
                except Exception as e:
                    print(f"[!] Error processing login event: {type(e).__name__}: {e}")
                    print(f"[!] Event: {json.dumps(item, indent=2)[:500]}")
                    import traceback
                    traceback.print_exc()

            # Get Drive events
            drive_enabled = CONFIG.get('drive', {}).get('enabled', True)
            if drive_enabled:
                drive_response = reports_service.activities().list(
                    userKey='all', applicationName='drive', startTime=start_time
                ).execute()
                
                # Debug: Print how many events were returned
                drives = drive_response.get('items', [])
                print(f"[DEBUG] Drive events: {len(drives)}")
                if drives:
                    print(f"[DEBUG] First drive event sample:")
                    print(json.dumps(drives[0], indent=2))
                
                for item in reversed(drives):
                    try:
                        process_drive_event(item, CONFIG)
                    except Exception as e:
                        print(f"[!] Error processing drive event: {type(e).__name__}: {e}")
                        print(f"[!] Event: {json.dumps(item, indent=2)[:500]}")
                        import traceback
                        traceback.print_exc()
            else:
                print("[DEBUG] Drive processor disabled via config")

        except Exception as e:
            print(f"[!] API error: {e}")

        last = now
        time.sleep(POLL_INTERVAL)

if __name__ == '__main__':
    main_loop()
