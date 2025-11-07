#!/usr/bin/env python3
"""
Log Pruning Script for Google Workspace Security Monitoring Agent

This script prunes old logs from the database based on the retention period
configured in config.json. It creates an archive SQL dump before deletion.

Run this script daily via cron or scheduled task.
"""

import os
import sys
import json
from datetime import datetime
from dotenv import load_dotenv
from db_helpers import prune_old_logs

# Load environment and config
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
load_dotenv(os.path.join(BASE_DIR, '.env'))

try:
    with open(os.path.join(BASE_DIR, 'config.json')) as f:
        CONFIG = json.load(f)
except FileNotFoundError:
    print("[!] Error: config.json not found")
    sys.exit(1)

def main():
    """Main pruning function."""
    retention_config = CONFIG.get('retention', {})
    retention_days = retention_config.get('retention_days', 180)
    archive_path = retention_config.get('archive_path', os.path.join(BASE_DIR, 'archives'))
    enable_archiving = retention_config.get('enable_archiving', True)
    
    print(f"[+] Starting log pruning at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"[+] Retention period: {retention_days} days")
    print(f"[+] Archive path: {archive_path}")
    print(f"[+] Archiving enabled: {enable_archiving}")
    
    # Prune old logs
    deleted_counts = prune_old_logs(
        retention_days=retention_days,
        archive_first=enable_archiving,
        archive_path=archive_path if enable_archiving else None
    )
    
    total_deleted = sum(deleted_counts.values())
    if total_deleted > 0:
        print(f"[+] Pruning completed: {total_deleted} records removed")
    else:
        print("[+] Pruning completed: No records to remove")
    
    return 0

if __name__ == '__main__':
    sys.exit(main())

