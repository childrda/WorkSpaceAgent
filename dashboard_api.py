#!/usr/bin/env python3
"""
Dashboard API Server for Google Workspace Security Monitoring Agent

Provides REST API endpoints for the security dashboard.
Run with: python dashboard_api.py
"""

import os
import json
from datetime import datetime, timedelta
from flask import Flask, jsonify, send_from_directory, request
from flask_cors import CORS
from dotenv import load_dotenv
from db_helpers import get_db_connection
from mysql.connector import Error

# Load environment
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
load_dotenv(os.path.join(BASE_DIR, '.env'))

app = Flask(__name__, static_folder='dashboard')
CORS(app)  # Enable CORS for frontend


def get_dashboard_stats():
    """Get overall dashboard statistics."""
    conn = get_db_connection()
    if not conn:
        return None
    
    try:
        cursor = conn.cursor(dictionary=True)
        
        # Count login attempts (last 7 days)
        week_ago = datetime.now() - timedelta(days=7)
        cursor.execute(
            "SELECT COUNT(*) as count FROM user_logins WHERE login_time >= %s",
            (week_ago,)
        )
        login_attempts = cursor.fetchone()['count']
        
        # Count impossible travel alerts
        cursor.execute(
            "SELECT COUNT(*) as count FROM security_alerts WHERE alert_type = 'impossible_travel'"
        )
        impossible_travel = cursor.fetchone()['count']
        
        # Count security alerts (last 7 days)
        cursor.execute(
            "SELECT COUNT(*) as count FROM security_alerts WHERE created_at >= %s",
            (week_ago,)
        )
        security_alerts = cursor.fetchone()['count']
        
        # Count phishing alerts (last 7 days)
        cursor.execute(
            "SELECT COUNT(*) as count FROM phishing_alerts WHERE created_at >= %s",
            (week_ago,)
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
               LIMIT 10"""
        )
        alerts = cursor.fetchall()
        
        # Get recent logins for these users to find location pairs
        travel_alerts = []
        for alert in alerts:
            email = alert['email']
            # Get last two logins for this user
            cursor.execute(
                """SELECT latitude, longitude, city, region, login_time
                   FROM user_logins
                   WHERE email = %s AND latitude IS NOT NULL AND longitude IS NOT NULL
                   ORDER BY login_time DESC
                   LIMIT 2""",
                (email,)
            )
            logins = cursor.fetchall()
            
            if len(logins) >= 2:
                travel_alerts.append({
                    'email': email,
                    'from': {
                        'city': logins[1].get('city', 'Unknown'),
                        'lat': float(logins[1]['latitude']),
                        'lon': float(logins[1]['longitude'])
                    },
                    'to': {
                        'city': logins[0].get('city', 'Unknown'),
                        'lat': float(logins[0]['latitude']),
                        'lon': float(logins[0]['longitude'])
                    },
                    'time': alert['created_at'].isoformat() if isinstance(alert['created_at'], datetime) else str(alert['created_at'])
                })
        
        cursor.close()
        conn.close()
        return travel_alerts
    except Error as e:
        print(f"[!] Error getting impossible travel alerts: {e}")
        return []


def get_recent_logins(limit=10):
    """Get recent login attempts."""
    conn = get_db_connection()
    if not conn:
        return []
    
    try:
        cursor = conn.cursor(dictionary=True)
        cursor.execute(
            """SELECT email, ip, login_time, city, region, country
               FROM user_logins
               ORDER BY login_time DESC
               LIMIT %s""",
            (limit,)
        )
        logins = cursor.fetchall()
        cursor.close()
        conn.close()
        
        return [{
            'time': login['login_time'].strftime('%Y-%m-%d') if isinstance(login['login_time'], datetime) else str(login['login_time']),
            'user': login['email'],
            'ip': login['ip'] or 'N/A',
            'location': f"{login['city'] or ''}, {login['region'] or ''}".strip(', ')
        } for login in logins]
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
               LIMIT 10"""
        )
        results = cursor.fetchall()
        cursor.close()
        conn.close()
        
        return {result['email']: result['count'] for result in results}
    except Error as e:
        print(f"[!] Error getting phishing alerts by recipient: {e}")
        return {}


def get_phishing_alerts(limit=10):
    """Get recent phishing alerts."""
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
        'recent_logins': get_recent_logins(10),
        'security_alerts_by_type': get_security_alerts_by_type(),
        'phishing_by_recipient': get_phishing_alerts_by_recipient(),
        'phishing_alerts': get_phishing_alerts(10)
    })


@app.route('/')
def index():
    """Serve the dashboard HTML."""
    return send_from_directory('dashboard', 'index.html')


@app.route('/<path:path>')
def serve_static(path):
    """Serve static files."""
    return send_from_directory('dashboard', path)


if __name__ == '__main__':
    print("[+] Starting Dashboard API server on http://localhost:5000")
    print("[+] Dashboard available at http://localhost:5000")
    app.run(host='0.0.0.0', port=5000, debug=True)

