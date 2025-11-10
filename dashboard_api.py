#!/usr/bin/env python3
"""
Dashboard API Server for Google Workspace Security Monitoring Agent

Provides REST API endpoints for the security dashboard.
Run with: python dashboard_api.py
"""

import os
import json
from datetime import datetime, timedelta, timezone
from flask import Flask, jsonify, send_from_directory, request
from flask_cors import CORS
from dotenv import load_dotenv
from db_helpers import get_db_connection
from mysql.connector import Error
from geo_utils import distance_miles
try:
    from zoneinfo import ZoneInfo
except ImportError:
    ZoneInfo = None

# Load environment and config
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
load_dotenv(os.path.join(BASE_DIR, '.env'))

# Load config once at startup
try:
    with open(os.path.join(BASE_DIR, 'config.json')) as f:
        CONFIG = json.load(f)
except FileNotFoundError:
    CONFIG = {}
    print("[!] Warning: config.json not found, using defaults")

app = Flask(__name__, static_folder='dashboard')
CORS(app)  # Enable CORS for frontend

DEFAULT_TZ_NAME = CONFIG.get('dashboard', {}).get('display_timezone', 'America/New_York')
if ZoneInfo:
    try:
        DISPLAY_TIMEZONE = ZoneInfo(DEFAULT_TZ_NAME)
    except Exception:
        print(f"[!] Warning: Could not load timezone '{DEFAULT_TZ_NAME}'. Falling back to America/New_York")
        DISPLAY_TIMEZONE = ZoneInfo('America/New_York') if ZoneInfo else None
else:
    print("[!] Warning: zoneinfo module unavailable. Login timestamps will display in UTC.")
    DISPLAY_TIMEZONE = None


def format_login_time(login_time):
    """Return login time string converted to configured timezone."""
    if not isinstance(login_time, datetime):
        return str(login_time)

    dt = login_time
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)

    if DISPLAY_TIMEZONE:
        dt = dt.astimezone(DISPLAY_TIMEZONE)
        return dt.strftime('%Y-%m-%d %I:%M:%S %p %Z')

    return dt.strftime('%Y-%m-%d %H:%M:%S UTC')


def get_dashboard_stats():
    """Get overall dashboard statistics."""
    lookback_days = CONFIG.get('dashboard', {}).get('stats_lookback_days', 7)
    
    conn = get_db_connection()
    if not conn:
        return None
    
    try:
        cursor = conn.cursor(dictionary=True)
        
        # Count login attempts (configurable lookback period)
        cutoff_date = datetime.now() - timedelta(days=lookback_days)
        cursor.execute(
            "SELECT COUNT(*) as count FROM user_logins WHERE login_time >= %s",
            (cutoff_date,)
        )
        login_attempts = cursor.fetchone()['count']
        
        # Count impossible travel alerts
        cursor.execute(
            "SELECT COUNT(*) as count FROM security_alerts WHERE alert_type = 'impossible_travel'"
        )
        impossible_travel = cursor.fetchone()['count']
        
        # Count security alerts (configurable lookback period)
        cursor.execute(
            "SELECT COUNT(*) as count FROM security_alerts WHERE created_at >= %s",
            (cutoff_date,)
        )
        security_alerts = cursor.fetchone()['count']
        
        # Count phishing alerts (configurable lookback period)
        cursor.execute(
            "SELECT COUNT(*) as count FROM phishing_alerts WHERE created_at >= %s",
            (cutoff_date,)
        )
        phishing_alerts = cursor.fetchone()['count']
        
        cursor.close()
        conn.close()
        
        return {
            'login_attempts': login_attempts,
            'impossible_travel': impossible_travel,
            'security_alerts': security_alerts,
            'phishing_alerts': phishing_alerts
        }
    except Error as e:
        print(f"[!] Error getting dashboard stats: {e}")
        return None


def get_impossible_travel_alerts():
    """Get impossible travel alerts with location data."""
    limit = CONFIG.get('dashboard', {}).get('query_limits', {}).get('impossible_travel', 10)
    
    conn = get_db_connection()
    if not conn:
        return []
    
    try:
        cursor = conn.cursor(dictionary=True)
        # Get impossible travel alerts and try to extract location info from details
        cursor.execute(
            """SELECT email, details, created_at
               FROM security_alerts
               WHERE alert_type = 'impossible_travel'
               ORDER BY created_at DESC
               LIMIT %s""",
            (limit,)
        )
        alerts = cursor.fetchall()
        
        # Get recent logins for these users to find location pairs
        travel_alerts = []
        for alert in alerts:
            email = alert['email']
            login_pairs_limit = CONFIG.get('dashboard', {}).get('query_limits', {}).get('login_pairs', 2)
            
            cursor.execute(
                """SELECT ip, latitude, longitude, city, region, country, login_time
                   FROM user_logins
                   WHERE email = %s AND latitude IS NOT NULL AND longitude IS NOT NULL
                   ORDER BY login_time DESC
                   LIMIT %s""",
                (email, login_pairs_limit)
            )
            logins = cursor.fetchall()
            
            if len(logins) >= 2:
                latest = logins[0]
                previous = logins[1]
                distance = None
                speed = None
                delta_minutes = None
                try:
                    distance = distance_miles(
                        float(previous['latitude']),
                        float(previous['longitude']),
                        float(latest['latitude']),
                        float(latest['longitude'])
                    )
                except (TypeError, ValueError):
                    distance = None

                latest_time = latest.get('login_time')
                previous_time = previous.get('login_time')
                if isinstance(latest_time, datetime) and isinstance(previous_time, datetime):
                    delta_hours = (latest_time - previous_time).total_seconds() / 3600
                    if delta_hours > 0:
                        delta_minutes = round(delta_hours * 60, 1)
                        if distance is not None:
                            speed = distance / delta_hours if delta_hours else None
                    if delta_hours <= 0 and distance is not None:
                        # Use absolute value for display but avoid division by zero
                        delta_minutes = round(abs(delta_hours) * 60, 1)

                travel_alerts.append({
                    'email': email,
                    'details': alert.get('details'),
                    'created_at': format_login_time(alert.get('created_at')),
                    'from': {
                        'city': previous.get('city', 'Unknown'),
                        'region': previous.get('region', 'Unknown'),
                        'country': previous.get('country', 'Unknown'),
                        'ip': previous.get('ip', 'N/A'),
                        'time': format_login_time(previous.get('login_time')),
                        'lat': float(previous['latitude']),
                        'lon': float(previous['longitude'])
                    },
                    'to': {
                        'city': latest.get('city', 'Unknown'),
                        'region': latest.get('region', 'Unknown'),
                        'country': latest.get('country', 'Unknown'),
                        'ip': latest.get('ip', 'N/A'),
                        'time': format_login_time(latest.get('login_time')),
                        'lat': float(latest['latitude']),
                        'lon': float(latest['longitude'])
                    },
                    'distance_miles': round(distance, 1) if distance is not None else None,
                    'speed_mph': round(speed, 1) if speed is not None else None,
                    'delta_minutes': delta_minutes
                })
 
        cursor.close()
        conn.close()
        return travel_alerts
    except Error as e:
        print(f"[!] Error getting impossible travel alerts: {e}")
        return []


def get_recent_logins(limit=None):
    """Get recent login attempts."""
    if limit is None:
        limit = CONFIG.get('dashboard', {}).get('query_limits', {}).get('recent_logins', 10)
    
    conn = get_db_connection()
    if not conn:
        return []
    
    try:
        cursor = conn.cursor(dictionary=True)
        cursor.execute(
            """SELECT email, ip, login_time, city, region, country, login_success
               FROM user_logins
               ORDER BY login_time DESC
               LIMIT %s""",
            (limit,)
        )
        logins = cursor.fetchall()
        cursor.close()
        conn.close()
        
        results = []
        for login in logins:
            success_flag = bool(login.get('login_success', True))
            results.append({
                'time': format_login_time(login.get('login_time')),
                'user': login.get('email') or 'Unknown',
                'ip': login.get('ip') or 'N/A',
                'location': f"{login.get('city') or ''}, {login.get('region') or ''}".strip(', '),
                'success': success_flag,
                'status': 'Success' if success_flag else 'Failed'
            })

        return results
    except Error as e:
        print(f"[!] Error getting recent logins: {e}")
        return []


def get_security_alerts_by_type():
    """Get count of security alerts by type."""
    conn = get_db_connection()
    if not conn:
        return {}
    
    try:
        cursor = conn.cursor(dictionary=True)
        cursor.execute(
            """SELECT alert_type, COUNT(*) as count
               FROM security_alerts
               GROUP BY alert_type"""
        )
        results = cursor.fetchall()
        cursor.close()
        conn.close()
        
        # Format for chart
        alerts_by_type = {}
        for result in results:
            alert_type = result['alert_type']
            # Map to display names
            if 'new_device' in alert_type.lower():
                alerts_by_type['New Device'] = alerts_by_type.get('New Device', 0) + result['count']
            elif 'suspicious' in alert_type.lower() or 'login' in alert_type.lower():
                alerts_by_type['Suspicious Login'] = alerts_by_type.get('Suspicious Login', 0) + result['count']
            else:
                alerts_by_type[alert_type] = result['count']
        
        return alerts_by_type
    except Error as e:
        print(f"[!] Error getting security alerts by type: {e}")
        return {}


def get_phishing_alerts_by_recipient():
    """Get count of phishing alerts by recipient."""
    limit = CONFIG.get('dashboard', {}).get('query_limits', {}).get('phishing_alerts', 10)
    
    conn = get_db_connection()
    if not conn:
        return {}
    
    try:
        cursor = conn.cursor(dictionary=True)
        cursor.execute(
            """SELECT email, COUNT(*) as count
               FROM phishing_alerts
               GROUP BY email
               ORDER BY count DESC
               LIMIT %s""",
            (limit,)
        )
        results = cursor.fetchall()
        cursor.close()
        conn.close()
        
        return {result['email']: result['count'] for result in results}
    except Error as e:
        print(f"[!] Error getting phishing alerts by recipient: {e}")
        return {}


def get_phishing_alerts(limit=None):
    """Get recent phishing alerts."""
    if limit is None:
        limit = CONFIG.get('dashboard', {}).get('query_limits', {}).get('phishing_alerts', 10)
    
    conn = get_db_connection()
    if not conn:
        return []
    
    try:
        cursor = conn.cursor(dictionary=True)
        cursor.execute(
            """SELECT email, owner_domain, created_at
               FROM phishing_alerts
               ORDER BY created_at DESC
               LIMIT %s""",
            (limit,)
        )
        alerts = cursor.fetchall()
        cursor.close()
        conn.close()
        
        return [{
            'recipient': alert['email'],
            'sender': alert['owner_domain'] or 'Unknown',
            'time': alert['created_at'].strftime('%Y-%m-%d') if isinstance(alert['created_at'], datetime) else str(alert['created_at'])
        } for alert in alerts]
    except Error as e:
        print(f"[!] Error getting phishing alerts: {e}")
        return []


@app.route('/api/stats', methods=['GET'])
def api_stats():
    """Get dashboard statistics."""
    stats = get_dashboard_stats()
    if stats is None:
        return jsonify({'error': 'Failed to fetch statistics'}), 500
    return jsonify(stats)


@app.route('/api/impossible-travel', methods=['GET'])
def api_impossible_travel():
    """Get impossible travel alerts."""
    alerts = get_impossible_travel_alerts()
    return jsonify(alerts)


@app.route('/api/recent-logins', methods=['GET'])
def api_recent_logins():
    """Get recent login attempts."""
    limit = int(request.args.get('limit', 10))
    logins = get_recent_logins(limit)
    return jsonify(logins)


@app.route('/api/security-alerts-by-type', methods=['GET'])
def api_security_alerts_by_type():
    """Get security alerts grouped by type."""
    alerts = get_security_alerts_by_type()
    return jsonify(alerts)


@app.route('/api/phishing-by-recipient', methods=['GET'])
def api_phishing_by_recipient():
    """Get phishing alerts grouped by recipient."""
    alerts = get_phishing_alerts_by_recipient()
    return jsonify(alerts)


@app.route('/api/phishing-alerts', methods=['GET'])
def api_phishing_alerts():
    """Get recent phishing alerts."""
    limit = int(request.args.get('limit', 10))
    alerts = get_phishing_alerts(limit)
    return jsonify(alerts)


@app.route('/api/dashboard', methods=['GET'])
def api_dashboard():
    """Get all dashboard data in one call."""
    return jsonify({
        'stats': get_dashboard_stats(),
        'impossible_travel': get_impossible_travel_alerts(),
        'recent_logins': get_recent_logins(100),
        'security_alerts_by_type': get_security_alerts_by_type(),
        'phishing_by_recipient': get_phishing_alerts_by_recipient(),
        'phishing_alerts': get_phishing_alerts(),
        'refresh_interval': get_refresh_interval()
    })


def get_refresh_interval():
    """Get dashboard refresh interval from config."""
    return CONFIG.get('dashboard', {}).get('refresh_interval_seconds', 30)


@app.route('/')
def index():
    """Serve the dashboard HTML."""
    return send_from_directory('dashboard', 'index.html')


@app.route('/<path:path>')
def serve_static(path):
    """Serve static files."""
    return send_from_directory('dashboard', path)


if __name__ == '__main__':
    # Get port from environment variable or config, default to 5000
    port = int(os.getenv('DASHBOARD_PORT', 5000))
    host = os.getenv('DASHBOARD_HOST', '0.0.0.0')
    
    print(f"[+] Starting Dashboard API server on http://{host}:{port}")
    print(f"[+] Dashboard available at http://localhost:{port}")
    app.run(host=host, port=port, debug=True)

