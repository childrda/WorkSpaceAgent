import os
import json
from datetime import datetime, timedelta
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


def create_archive_dump(archive_path, retention_days):
    """
    Create an SQL dump of data that will be pruned before deletion.
    Returns the path to the created dump file, or None on failure.
    """
    if not os.path.exists(archive_path):
        try:
            os.makedirs(archive_path, exist_ok=True)
        except Exception as e:
            print(f"[!] Failed to create archive directory: {e}")
            return None

    # Calculate cutoff date
    cutoff_date = datetime.now() - timedelta(days=retention_days)
    cutoff_str = cutoff_date.strftime('%Y-%m-%d %H:%M:%S')
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    
    db_name = os.getenv('MYSQL_DB')
    db_host = os.getenv('MYSQL_HOST', 'localhost')
    db_port = os.getenv('MYSQL_PORT', '3306')
    db_user = os.getenv('MYSQL_USER')
    db_password = os.getenv('MYSQL_PASSWORD')
    
    dump_file = os.path.join(archive_path, f"archive_{timestamp}.sql")
    
    try:
        # Use mysqldump to create archive
        # First, get the data that will be deleted
        conn = get_db_connection()
        if not conn:
            return None
        
        cursor = conn.cursor()
        
        # Create archive SQL file
        with open(dump_file, 'w', encoding='utf-8') as f:
            f.write(f"-- Archive created on {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"-- Data older than {cutoff_str} (retention: {retention_days} days)\n\n")
            f.write(f"SET FOREIGN_KEY_CHECKS=0;\n\n")
            
            def escape_sql(value):
                """Escape a value for SQL insertion."""
                if value is None:
                    return 'NULL'
                if isinstance(value, (int, float)):
                    return str(value)
                # Escape single quotes and backslashes for MySQL
                escaped = str(value).replace('\\', '\\\\').replace("'", "''")
                return f"'{escaped}'"
            
            # Archive user_logins
            cursor.execute(
                """SELECT * FROM user_logins 
                   WHERE login_time < %s 
                   ORDER BY login_time""",
                (cutoff_date,)
            )
            rows = cursor.fetchall()
            if rows:
                f.write("-- user_logins archive\n")
                f.write("INSERT INTO user_logins (id, email, ip, latitude, longitude, country, region, city, asn, login_time, created_at) VALUES\n")
                values = []
                for row in rows:
                    val_str = f"({row[0]}, {escape_sql(row[1])}, {escape_sql(row[2])}, {escape_sql(row[3])}, {escape_sql(row[4])}, {escape_sql(row[5])}, {escape_sql(row[6])}, {escape_sql(row[7])}, {escape_sql(row[8])}, {escape_sql(row[9])}, {escape_sql(row[10])})"
                    values.append(val_str)
                f.write(",\n".join(values) + ";\n\n")
            
            # Archive security_alerts
            cursor.execute(
                """SELECT * FROM security_alerts 
                   WHERE created_at < %s 
                   ORDER BY created_at""",
                (cutoff_date,)
            )
            rows = cursor.fetchall()
            if rows:
                f.write("-- security_alerts archive\n")
                f.write("INSERT INTO security_alerts (id, email, alert_type, details, created_at) VALUES\n")
                values = []
                for row in rows:
                    val_str = f"({row[0]}, {escape_sql(row[1])}, {escape_sql(row[2])}, {escape_sql(row[3])}, {escape_sql(row[4])})"
                    values.append(val_str)
                f.write(",\n".join(values) + ";\n\n")
            
            # Archive phishing_alerts
            cursor.execute(
                """SELECT * FROM phishing_alerts 
                   WHERE created_at < %s 
                   ORDER BY created_at""",
                (cutoff_date,)
            )
            rows = cursor.fetchall()
            if rows:
                f.write("-- phishing_alerts archive\n")
                f.write("INSERT INTO phishing_alerts (id, email, owner_domain, owner_display_name, file_id, file_title, file_link, visibility, visibility_change, reason, raw_event, alerted, created_at) VALUES\n")
                values = []
                for row in rows:
                    val_str = f"({row[0]}, {escape_sql(row[1])}, {escape_sql(row[2])}, {escape_sql(row[3])}, {escape_sql(row[4])}, {escape_sql(row[5])}, {escape_sql(row[6])}, {escape_sql(row[7])}, {escape_sql(row[8])}, {escape_sql(row[9])}, {escape_sql(row[10])}, {1 if row[11] else 0}, {escape_sql(row[12])})"
                    values.append(val_str)
                f.write(",\n".join(values) + ";\n\n")
            
            f.write("SET FOREIGN_KEY_CHECKS=1;\n")
        
        cursor.close()
        conn.close()
        
        print(f"[+] Archive created: {dump_file}")
        return dump_file
        
    except Exception as e:
        print(f"[!] Failed to create archive dump: {e}")
        return None


def prune_old_logs(retention_days, archive_first=True, archive_path=None):
    """
    Prune logs older than retention_days from the database.
    If archive_first is True, creates an archive dump before deletion.
    Returns dict with counts of deleted records.
    """
    cutoff_date = datetime.now() - timedelta(days=retention_days)
    deleted_counts = {
        'user_logins': 0,
        'security_alerts': 0,
        'phishing_alerts': 0
    }
    
    # Create archive if requested
    if archive_first and archive_path:
        archive_file = create_archive_dump(archive_path, retention_days)
        if not archive_file:
            print("[!] Archive creation failed, aborting prune to prevent data loss")
            return deleted_counts
    
    conn = get_db_connection()
    if not conn:
        return deleted_counts
    
    try:
        cursor = conn.cursor()
        
        # Prune user_logins (uses login_time)
        cursor.execute(
            "DELETE FROM user_logins WHERE login_time < %s",
            (cutoff_date,)
        )
        deleted_counts['user_logins'] = cursor.rowcount
        
        # Prune security_alerts (uses created_at)
        cursor.execute(
            "DELETE FROM security_alerts WHERE created_at < %s",
            (cutoff_date,)
        )
        deleted_counts['security_alerts'] = cursor.rowcount
        
        # Prune phishing_alerts (uses created_at)
        cursor.execute(
            "DELETE FROM phishing_alerts WHERE created_at < %s",
            (cutoff_date,)
        )
        deleted_counts['phishing_alerts'] = cursor.rowcount
        
        conn.commit()
        cursor.close()
        conn.close()
        
        total_deleted = sum(deleted_counts.values())
        print(f"[+] Pruned {total_deleted} records older than {retention_days} days")
        print(f"    - user_logins: {deleted_counts['user_logins']}")
        print(f"    - security_alerts: {deleted_counts['security_alerts']}")
        print(f"    - phishing_alerts: {deleted_counts['phishing_alerts']}")
        
        return deleted_counts
        
    except Error as e:
        print(f"[!] Failed to prune logs: {e}")
        conn.rollback()
        return deleted_counts
