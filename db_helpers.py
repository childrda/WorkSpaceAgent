import os
import json
import mysql.connector
from mysql.connector import Error


def get_db_connection():
    """
    Establish a connection to the MySQL database using credentials from .env.
    Returns a connection object or None if failed.
    """
    try:
        conn = mysql.connector.connect(
            host=os.getenv('MYSQL_HOST', 'localhost'),
            port=int(os.getenv('MYSQL_PORT', 3306)),
            user=os.getenv('MYSQL_USER'),
            password=os.getenv('MYSQL_PASSWORD'),
            database=os.getenv('MYSQL_DB')
        )
        return conn
    except Error as e:
        print(f"[!] MySQL connection error: {e}")
        return None


def insert_security_alert(email, alert_type, details):
    """
    Store a new security alert (e.g., new device or impossible travel).
    """
    conn = get_db_connection()
    if not conn:
        return False

    try:
        cursor = conn.cursor()
        cursor.execute(
            "INSERT INTO security_alerts (email, alert_type, details) VALUES (%s, %s, %s)",
            (email, alert_type, details)
        )
        conn.commit()
        cursor.close()
        conn.close()
        return True
    except Error as e:
        print(f"[!] security_alert insert error: {e}")
        return False


def insert_user_login(email, ip, latitude, longitude, country, region, city, login_time):
    """
    Store a user login event in the database for tracking location history.
    """
    conn = get_db_connection()
    if not conn:
        return False

    try:
        cursor = conn.cursor()
        cursor.execute(
            """INSERT INTO user_logins 
               (email, ip, latitude, longitude, country, region, city, login_time) 
               VALUES (%s, %s, %s, %s, %s, %s, %s, %s)""",
            (email, ip, latitude, longitude, country, region, city, login_time)
        )
        conn.commit()
        cursor.close()
        conn.close()
        return True
    except Error as e:
        print(f"[!] user_login insert error: {e}")
        return False


def get_last_login_location(email):
    """
    Retrieve the most recent login location for a user from the database.
    Returns dict with latitude, longitude, region, city, country, and login_time, or None.
    """
    conn = get_db_connection()
    if not conn:
        return None

    try:
        cursor = conn.cursor(dictionary=True)
        cursor.execute(
            """SELECT latitude, longitude, region, city, country, login_time 
               FROM user_logins 
               WHERE email = %s AND latitude IS NOT NULL AND longitude IS NOT NULL
               ORDER BY login_time DESC 
               LIMIT 1""",
            (email,)
        )
        result = cursor.fetchone()
        cursor.close()
        conn.close()
        return result
    except Error as e:
        print(f"[!] get_last_login_location error: {e}")
        return None


def insert_phishing_alert(email, owner_domain, owner_display_name, file_id, file_title,
                          file_link, visibility, visibility_change, reason, raw_event, alerted=True):
    """
    Store a phishing or impersonation alert from Google Drive event logs.
    """
    conn = get_db_connection()
    if not conn:
        print("[!] Skipping DB insert: connection failed")
        return False

    try:
        cursor = conn.cursor()
        sql = """
        INSERT INTO phishing_alerts
        (email, owner_domain, owner_display_name, file_id, file_title, file_link,
         visibility, visibility_change, reason, raw_event, alerted)
        VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
        """
        cursor.execute(sql, (
            email,
            owner_domain,
            owner_display_name,
            file_id,
            file_title,
            file_link,
            visibility,
            visibility_change,
            reason,
            json.dumps(raw_event),
            int(alerted)
        ))
        conn.commit()
        cursor.close()
        conn.close()
        return True
    except Error as e:
        print(f"[!] phishing_alert insert error: {e}")
        return False
