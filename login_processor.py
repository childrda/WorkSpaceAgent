from datetime import datetime
import json
from geo_utils import ip_to_geo, distance_miles
from alert_utils import send_email_alert
from db_helpers import insert_security_alert, insert_user_login, get_last_login_location

# In-memory cache for last known login location (to avoid constant DB hits)
last_login_cache = {}


def process_login_event(item, sec_alerts_dict, CONFIG):
    """
    Process a Google Workspace login event.
    Detects impossible travel and correlates with security alerts.
    sec_alerts_dict: dict mapping user email to alert info (from fetch_security_alerts)
    """
    params = {p['name']: p.get('value') for p in item.get('parameters', [])}
    ip = params.get('ipAddress')
    actor = item.get('actor', {}).get('email')
    if not actor:
        return
    
    timestamp = datetime.strptime(item['id']['time'], '%Y-%m-%dT%H:%M:%S.%fZ')

    # Geolocate the IP
    geo = ip_to_geo(ip, CONFIG['geo_db_path'])

    # Alert if the IP lookup fails for an external address
    if geo.get('error') and geo['error'] not in ('private_ip', 'no_ip'):
        send_email_alert(f"Geo lookup failed for {actor}", json.dumps(geo, indent=2))

    # Store login in database for historical tracking
    if geo.get('latitude') and geo.get('longitude'):
        insert_user_login(
            actor,
            ip,
            geo.get('latitude'),
            geo.get('longitude'),
            geo.get('country'),
            geo.get('region'),
            geo.get('city'),
            timestamp
        )

    # Cross-reference: Is this user in a "new device" security alert?
    if actor in sec_alerts_dict:
        alert_info = sec_alerts_dict[actor]
        is_new_device = alert_info.get('is_new_device', False)
        
        if is_new_device:
            # Check if current location is in VA state
            current_state = geo.get('region', '')
            is_in_va = 'virginia' in current_state.lower() or 'va' in current_state.lower()
            
            # Get last login location from database
            last_login = get_last_login_location(actor)
            
            if last_login:
                last_state = last_login.get('region', '')
                last_is_in_va = 'virginia' in last_state.lower() or 'va' in last_state.lower()
                
                # Alert if current login is not in VA
                if not is_in_va:
                    msg = (
                        f"Security Alert: New Device Login Outside VA\n\n"
                        f"User: {actor}\n"
                        f"Alert: {alert_info.get('title', 'New Device')}\n"
                        f"Current Location: {geo.get('city', 'Unknown')}, {current_state}, {geo.get('country', 'Unknown')}\n"
                        f"IP: {ip}\n"
                        f"Last Login Location: {last_login.get('city', 'Unknown')}, {last_state}, {last_login.get('country', 'Unknown')}\n"
                        f"Login Time: {timestamp}\n"
                    )
                    subject = f"{CONFIG['alerts']['alert_subject_prefix']} New Device Login Outside VA: {actor}"
                    send_email_alert(subject, msg)
                    insert_security_alert(actor, "new_device_outside_va", msg)
                else:
                    # Still log the new device login even if in VA
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
                # No previous login found, but still alert if not in VA
                if not is_in_va:
                    msg = (
                        f"Security Alert: New Device Login Outside VA (No Previous Login Found)\n\n"
                        f"User: {actor}\n"
                        f"Alert: {alert_info.get('title', 'New Device')}\n"
                        f"Current Location: {geo.get('city', 'Unknown')}, {current_state}, {geo.get('country', 'Unknown')}\n"
                        f"IP: {ip}\n"
                        f"Login Time: {timestamp}\n"
                    )
                    subject = f"{CONFIG['alerts']['alert_subject_prefix']} New Device Login Outside VA: {actor}"
                    send_email_alert(subject, msg)
                    insert_security_alert(actor, "new_device_outside_va", msg)

    # Impossible Travel Detection
    if actor in last_login_cache:
        last = last_login_cache[actor]
        if geo.get('latitude') and last.get('lat'):
            dist = distance_miles(last['lat'], last['lon'], geo['latitude'], geo['longitude'])
            delta = (timestamp - last['time']).total_seconds() / 3600  # hours

            if delta > 0 and dist / delta > 500:  # 500 mph threshold
                msg = (
                    f"User: {actor}\n"
                    f"Distance: {dist:.1f} miles in {delta:.1f} hours\n"
                    f"Previous Location: ({last['lat']}, {last['lon']})\n"
                    f"New Location: ({geo['latitude']}, {geo['longitude']})\n"
                    f"Previous: {last.get('city', 'Unknown')}, {last.get('region', 'Unknown')}\n"
                    f"Current: {geo.get('city', 'Unknown')}, {geo.get('region', 'Unknown')}"
                )
                subject = f"{CONFIG['alerts']['alert_subject_prefix']} Impossible Travel Alert: {actor}"
                send_email_alert(subject, msg)
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

            if delta > 0 and dist / delta > 500:  # 500 mph threshold
                msg = (
                    f"User: {actor}\n"
                    f"Distance: {dist:.1f} miles in {delta:.1f} hours\n"
                    f"Previous Location: ({last_login['latitude']}, {last_login['longitude']})\n"
                    f"New Location: ({geo['latitude']}, {geo['longitude']})\n"
                    f"Previous: {last_login.get('city', 'Unknown')}, {last_login.get('region', 'Unknown')}\n"
                    f"Current: {geo.get('city', 'Unknown')}, {geo.get('region', 'Unknown')}"
                )
                subject = f"{CONFIG['alerts']['alert_subject_prefix']} Impossible Travel Alert: {actor}"
                send_email_alert(subject, msg)
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
