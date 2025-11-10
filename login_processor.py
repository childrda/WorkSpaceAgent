from datetime import datetime
import json
from geo_utils import ip_to_geo, distance_miles
from alert_utils import send_email_alert
from db_helpers import insert_security_alert, insert_user_login, get_last_login_location

# In-memory cache for last known login location (to avoid constant DB hits)
last_login_cache = {}


def _extract_parameter_value(param):
    """Return the most useful value from a Google Workspace event parameter."""
    if not isinstance(param, dict):
        return None

    for key in ("value", "stringValue", "intValue", "boolValue"):
        if param.get(key) is not None:
            return param[key]

    if param.get("multiValue"):
        return param["multiValue"]

    return None


def process_login_event(item, sec_alerts_dict, CONFIG):
    """
    Process a Google Workspace login event.
    Detects impossible travel and correlates with security alerts.
    sec_alerts_dict: dict mapping user email to alert info (from fetch_security_alerts)
    """
    try:
        params = {}
        for param in item.get('parameters', []):
            name = param.get('name')
            if name:
                params[name] = _extract_parameter_value(param)

        for event in item.get('events', []):
            for param in event.get('parameters', []):
                name = param.get('name')
                if name and name not in params:
                    params[name] = _extract_parameter_value(param)

        ip = (
            params.get('ipAddress')
            or item.get('ipAddress')
            or item.get('actor', {}).get('callerIpAddress')
            or item.get('id', {}).get('callerIpAddress')
        )
        actor = item.get('actor', {}).get('email')
        event_name = item.get('name', '')
        
        # Determine if login was successful based on event name
        # Google Workspace typically uses: login_success, login_failure, etc.
        login_success = True  # Default to success
        if 'failure' in event_name.lower() or 'denied' in event_name.lower() or 'blocked' in event_name.lower():
            login_success = False
        
        if CONFIG.get('log_level', 'INFO').upper() == 'DEBUG':
            print("[DEBUG] Full login event from Google Workspace:")
            print(json.dumps(item, indent=2))
            print(f"[DEBUG] Parsed parameters: {json.dumps(params, indent=2)}")

        if not ip:
            print(f"[!] Login event missing IP address for {actor}. Event: {json.dumps(item, indent=2)[:300]}")
        else:
            ip = str(ip)

        if not actor:
            print(f"[!] Skipping login event - no actor email found. Event: {json.dumps(item, indent=2)[:200]}")
            return
        
        try:
            timestamp = datetime.strptime(item['id']['time'], '%Y-%m-%dT%H:%M:%S.%fZ')
        except ValueError as e:
            print(f"[!] Failed to parse timestamp for {actor}: {item.get('id', {}).get('time')} - {e}")
            return
    except Exception as e:
        print(f"[!] Error parsing login event: {type(e).__name__}: {e}")
        print(f"[!] Event data: {json.dumps(item, indent=2)[:500]}")
        return

    # Geolocate the IP
    geo = ip_to_geo(ip, CONFIG['geo_db_path']) if ip else {'ip': None}
    ip_to_store = ip or geo.get('ip')

    # Alert if the IP lookup fails for an external address
    if geo.get('error') and geo['error'] not in ('private_ip', 'no_ip'):
        send_email_alert(f"Geo lookup failed for {actor}", json.dumps(geo, indent=2), CONFIG)

    # Store login in database for historical tracking (store all logins, even without geo data)
    success = insert_user_login(
        actor,
        ip_to_store,
        geo.get('latitude'),
        geo.get('longitude'),
        geo.get('country', 'Unknown'),
        geo.get('region', 'Unknown'),
        geo.get('city', 'Unknown'),
        timestamp,
        login_success
    )
    if not success:
        print(f"[!] Failed to store login for {actor} at {timestamp} (IP: {ip_to_store})")
    else:
        print(f"[DEBUG] Stored login for {actor} - IP: {ip_to_store}, Location: {geo.get('city', 'Unknown')}, {geo.get('region', 'Unknown')}")

    # Cross-reference: Is this user in a "new device" security alert?
    if actor in sec_alerts_dict:
        alert_info = sec_alerts_dict[actor]
        is_new_device = alert_info.get('is_new_device', False)
        
        if is_new_device:
            # Check if state checking is enabled and if current location is in allowed states
            state_check_enabled = CONFIG.get('security', {}).get('state_check_enabled', True)
            allowed_states = CONFIG.get('security', {}).get('allowed_states', ['VA', 'Virginia'])
            
            current_state = geo.get('region', '')
            is_in_allowed_state = False
            if state_check_enabled and allowed_states:
                is_in_allowed_state = any(
                    state.lower() in current_state.lower() 
                    for state in allowed_states
                )
            
            # Get last login location from database
            last_login = get_last_login_location(actor)
            
            if last_login:
                last_state = last_login.get('region', '')
                last_is_in_allowed_state = False
                if state_check_enabled and allowed_states:
                    last_is_in_allowed_state = any(
                        state.lower() in last_state.lower() 
                        for state in allowed_states
                    )
                
                # Alert if current login is not in allowed state
                if state_check_enabled and not is_in_allowed_state:
                    state_list = ', '.join(allowed_states)
                    msg = (
                        f"Security Alert: New Device Login Outside Allowed States ({state_list})\n\n"
                        f"User: {actor}\n"
                        f"Alert: {alert_info.get('title', 'New Device')}\n"
                        f"Current Location: {geo.get('city', 'Unknown')}, {current_state}, {geo.get('country', 'Unknown')}\n"
                        f"IP: {ip}\n"
                        f"Last Login Location: {last_login.get('city', 'Unknown')}, {last_state}, {last_login.get('country', 'Unknown')}\n"
                        f"Login Time: {timestamp}\n"
                    )
                    subject = f"{CONFIG['alerts']['alert_subject_prefix']} New Device Login Outside Allowed States: {actor}"
                    send_email_alert(subject, msg, CONFIG)
                    insert_security_alert(actor, "new_device_outside_allowed_state", msg)
                else:
                    # Still log the new device login even if in allowed state
                    msg = (
                        f"Security Alert: New Device Login Detected\n\n"
                        f"User: {actor}\n"
                        f"Alert: {alert_info.get('title', 'New Device')}\n"
                        f"Location: {geo.get('city', 'Unknown')}, {current_state}, {geo.get('country', 'Unknown')}\n"
                        f"IP: {ip}\n"
                        f"Login Time: {timestamp}\n"
                    )
                    insert_security_alert(actor, "new_device_login", msg)
            else:
                # No previous login found, but still alert if not in allowed state
                if state_check_enabled and not is_in_allowed_state:
                    state_list = ', '.join(allowed_states)
                    msg = (
                        f"Security Alert: New Device Login Outside Allowed States ({state_list}) (No Previous Login Found)\n\n"
                        f"User: {actor}\n"
                        f"Alert: {alert_info.get('title', 'New Device')}\n"
                        f"Current Location: {geo.get('city', 'Unknown')}, {current_state}, {geo.get('country', 'Unknown')}\n"
                        f"IP: {ip}\n"
                        f"Login Time: {timestamp}\n"
                    )
                    subject = f"{CONFIG['alerts']['alert_subject_prefix']} New Device Login Outside Allowed States: {actor}"
                    send_email_alert(subject, msg, CONFIG)
                    insert_security_alert(actor, "new_device_outside_allowed_state", msg)

    # Impossible Travel Detection
    impossible_travel_threshold = CONFIG.get('security', {}).get('impossible_travel_threshold_mph', 500)
    
    if actor in last_login_cache:
        last = last_login_cache[actor]
        if geo.get('latitude') and last.get('lat'):
            dist = distance_miles(last['lat'], last['lon'], geo['latitude'], geo['longitude'])
            delta = (timestamp - last['time']).total_seconds() / 3600  # hours

            if delta > 0 and dist / delta > impossible_travel_threshold:
                msg = (
                    f"User: {actor}\n"
                    f"Distance: {dist:.1f} miles in {delta:.1f} hours\n"
                    f"Previous Location: ({last['lat']}, {last['lon']})\n"
                    f"New Location: ({geo['latitude']}, {geo['longitude']})\n"
                    f"Previous: {last.get('city', 'Unknown')}, {last.get('region', 'Unknown')}\n"
                    f"Current: {geo.get('city', 'Unknown')}, {geo.get('region', 'Unknown')}"
                )
                subject = f"{CONFIG['alerts']['alert_subject_prefix']} Impossible Travel Alert: {actor}"
                send_email_alert(subject, msg, CONFIG)
                insert_security_alert(actor, "impossible_travel", msg)
    else:
        # Try to load from database if not in cache
        last_login = get_last_login_location(actor)
        if last_login and geo.get('latitude'):
            dist = distance_miles(
                last_login['latitude'], 
                last_login['longitude'], 
                geo['latitude'], 
                geo['longitude']
            )
            last_time = last_login['login_time']
            if isinstance(last_time, str):
                last_time = datetime.strptime(last_time, '%Y-%m-%d %H:%M:%S')
            delta = (timestamp - last_time).total_seconds() / 3600  # hours

            if delta > 0 and dist / delta > impossible_travel_threshold:
                msg = (
                    f"User: {actor}\n"
                    f"Distance: {dist:.1f} miles in {delta:.1f} hours\n"
                    f"Previous Location: ({last_login['latitude']}, {last_login['longitude']})\n"
                    f"New Location: ({geo['latitude']}, {geo['longitude']})\n"
                    f"Previous: {last_login.get('city', 'Unknown')}, {last_login.get('region', 'Unknown')}\n"
                    f"Current: {geo.get('city', 'Unknown')}, {geo.get('region', 'Unknown')}"
                )
                subject = f"{CONFIG['alerts']['alert_subject_prefix']} Impossible Travel Alert: {actor}"
                send_email_alert(subject, msg, CONFIG)
                insert_security_alert(actor, "impossible_travel", msg)

    # Cache latest login
    if geo.get('latitude'):
        last_login_cache[actor] = {
            'time': timestamp,
            'lat': geo['latitude'],
            'lon': geo['longitude'],
            'city': geo.get('city'),
            'region': geo.get('region'),
            'country': geo.get('country')
        }
