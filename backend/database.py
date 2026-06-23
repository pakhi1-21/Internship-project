"""
NetSight - Database Module (MODULE 8)
============================================
SQLite database layer providing schema creation, CRUD operations, and
query functions for traffic logs, alerts, anomalies, and settings.

Purpose:
    - Initialize and manage SQLite database
    - Store captured packet data (traffic_logs)
    - Store security alerts from all detection engines
    - Store AI anomaly detection results
    - Store application settings
    - Store aggregated traffic statistics
    - Provide parameterized queries for SQL injection prevention
    - Data retention management (cleanup old records)

Tables:
    - traffic_logs: Raw packet capture data
    - alerts: Security alerts from all detectors
    - anomalies: AI anomaly detection results
    - settings: Application configuration key-value store
    - traffic_stats: Aggregated traffic statistics snapshots
"""

import sqlite3
import json
import os
from datetime import datetime, timedelta
from contextlib import contextmanager

from config import DATABASE_PATH, DATABASE_DIR, DATA_RETENTION_DAYS
from backend.logger import get_system_logger

logger = get_system_logger('Database')

# Ensure database directory exists
os.makedirs(DATABASE_DIR, exist_ok=True)


# ============================================================
# CONNECTION MANAGEMENT
# ============================================================
@contextmanager
def get_db_connection():
    """
    Context manager for database connections.
    Ensures connections are properly closed and uses WAL mode for
    better concurrent read/write performance.

    Yields:
        sqlite3.Connection with Row factory enabled

    Usage:
        with get_db_connection() as conn:
            cursor = conn.execute("SELECT * FROM alerts")
            rows = cursor.fetchall()
    """
    conn = sqlite3.connect(DATABASE_PATH, timeout=10)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    try:
        yield conn
        conn.commit()
    except Exception as e:
        conn.rollback()
        logger.error('Database error: %s', str(e))
        raise
    finally:
        conn.close()


# ============================================================
# SCHEMA CREATION
# ============================================================
def init_db():
    """
    Initialize the database by creating all required tables if they
    don't already exist. Safe to call multiple times.

    Tables Created:
        - traffic_logs: Stores raw packet capture data
        - alerts: Stores security alerts from all detection modules
        - anomalies: Stores AI anomaly detection results
        - settings: Key-value application configuration store
        - traffic_stats: Aggregated traffic statistics snapshots
    """
    with get_db_connection() as conn:
        # ---- traffic_logs ----
        conn.execute('''
            CREATE TABLE IF NOT EXISTS traffic_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                src_ip TEXT NOT NULL,
                dst_ip TEXT NOT NULL,
                src_port INTEGER,
                dst_port INTEGER,
                protocol TEXT NOT NULL,
                packet_size INTEGER NOT NULL,
                flags TEXT,
                info TEXT
            )
        ''')

        # ---- alerts ----
        conn.execute('''
            CREATE TABLE IF NOT EXISTS alerts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                alert_type TEXT NOT NULL,
                severity TEXT NOT NULL,
                source_ip TEXT,
                destination_ip TEXT,
                description TEXT NOT NULL,
                details TEXT,
                resolved INTEGER DEFAULT 0,
                resolved_at TEXT
            )
        ''')

        # ---- anomalies ----
        conn.execute('''
            CREATE TABLE IF NOT EXISTS anomalies (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                threat_score REAL NOT NULL,
                classification TEXT NOT NULL,
                features_json TEXT,
                details TEXT
            )
        ''')

        # ---- settings ----
        conn.execute('''
            CREATE TABLE IF NOT EXISTS settings (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                key TEXT UNIQUE NOT NULL,
                value TEXT,
                updated_at TEXT NOT NULL
            )
        ''')

        # ---- traffic_stats ----
        conn.execute('''
            CREATE TABLE IF NOT EXISTS traffic_stats (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                packets_per_second REAL,
                active_connections INTEGER,
                total_bytes INTEGER,
                protocol_distribution TEXT,
                top_source_ips TEXT,
                top_dest_ports TEXT
            )
        ''')

        # ---- Indexes for performance ----
        conn.execute('CREATE INDEX IF NOT EXISTS idx_traffic_timestamp ON traffic_logs(timestamp)')
        conn.execute('CREATE INDEX IF NOT EXISTS idx_traffic_src_ip ON traffic_logs(src_ip)')
        conn.execute('CREATE INDEX IF NOT EXISTS idx_traffic_dst_ip ON traffic_logs(dst_ip)')
        conn.execute('CREATE INDEX IF NOT EXISTS idx_alerts_timestamp ON alerts(timestamp)')
        conn.execute('CREATE INDEX IF NOT EXISTS idx_alerts_type ON alerts(alert_type)')
        conn.execute('CREATE INDEX IF NOT EXISTS idx_alerts_severity ON alerts(severity)')
        conn.execute('CREATE INDEX IF NOT EXISTS idx_anomalies_timestamp ON anomalies(timestamp)')
        conn.execute('CREATE INDEX IF NOT EXISTS idx_stats_timestamp ON traffic_stats(timestamp)')

    logger.info('Database initialized successfully at %s', DATABASE_PATH)


# ============================================================
# TRAFFIC LOG OPERATIONS
# ============================================================
def insert_traffic_log(packet_data):
    """
    Insert a single packet record into the traffic_logs table.

    Args:
        packet_data: Dict with keys: timestamp, src_ip, dst_ip,
                     src_port, dst_port, protocol, packet_size, flags, info
    """
    with get_db_connection() as conn:
        conn.execute('''
            INSERT INTO traffic_logs
            (timestamp, src_ip, dst_ip, src_port, dst_port, protocol, packet_size, flags, info)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            packet_data.get('timestamp', datetime.now().isoformat()),
            packet_data.get('src_ip', ''),
            packet_data.get('dst_ip', ''),
            packet_data.get('src_port'),
            packet_data.get('dst_port'),
            packet_data.get('protocol', 'UNKNOWN'),
            packet_data.get('packet_size', 0),
            packet_data.get('flags', ''),
            packet_data.get('info', '')
        ))


def insert_traffic_logs_batch(packet_list):
    """
    Batch insert multiple packet records for better performance.

    Args:
        packet_list: List of dicts, each with packet data fields
    """
    if not packet_list:
        return

    with get_db_connection() as conn:
        conn.executemany('''
            INSERT INTO traffic_logs
            (timestamp, src_ip, dst_ip, src_port, dst_port, protocol, packet_size, flags, info)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', [
            (
                p.get('timestamp', datetime.now().isoformat()),
                p.get('src_ip', ''),
                p.get('dst_ip', ''),
                p.get('src_port'),
                p.get('dst_port'),
                p.get('protocol', 'UNKNOWN'),
                p.get('packet_size', 0),
                p.get('flags', ''),
                p.get('info', '')
            )
            for p in packet_list
        ])


def get_recent_traffic(limit=100, offset=0, protocol=None, src_ip=None):
    """
    Retrieve recent traffic logs with optional filtering.

    Args:
        limit: Maximum number of records to return
        offset: Number of records to skip (for pagination)
        protocol: Filter by protocol (TCP, UDP, ICMP)
        src_ip: Filter by source IP address

    Returns:
        List of dict records from traffic_logs
    """
    query = 'SELECT * FROM traffic_logs WHERE 1=1'
    params = []

    if protocol:
        query += ' AND protocol = ?'
        params.append(protocol)
    if src_ip:
        query += ' AND src_ip = ?'
        params.append(src_ip)

    query += ' ORDER BY id DESC LIMIT ? OFFSET ?'
    params.extend([limit, offset])

    with get_db_connection() as conn:
        cursor = conn.execute(query, params)
        return [dict(row) for row in cursor.fetchall()]


def get_traffic_count(since_minutes=None):
    """
    Get the total number of traffic log entries.

    Args:
        since_minutes: If provided, count only entries from the last N minutes

    Returns:
        Integer count of traffic log entries
    """
    with get_db_connection() as conn:
        if since_minutes:
            since = (datetime.now() - timedelta(minutes=since_minutes)).isoformat()
            cursor = conn.execute(
                'SELECT COUNT(*) FROM traffic_logs WHERE timestamp >= ?', (since,)
            )
        else:
            cursor = conn.execute('SELECT COUNT(*) FROM traffic_logs')
        return cursor.fetchone()[0]


# ============================================================
# ALERT OPERATIONS
# ============================================================
def insert_alert(alert_data):
    """
    Insert a security alert record.

    Args:
        alert_data: Dict with keys: timestamp, alert_type, severity,
                    source_ip, destination_ip, description, details

    Returns:
        The ID of the newly inserted alert
    """
    with get_db_connection() as conn:
        cursor = conn.execute('''
            INSERT INTO alerts
            (timestamp, alert_type, severity, source_ip, destination_ip, description, details)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        ''', (
            alert_data.get('timestamp', datetime.now().isoformat()),
            alert_data.get('alert_type', ''),
            alert_data.get('severity', 'LOW'),
            alert_data.get('source_ip', ''),
            alert_data.get('destination_ip', ''),
            alert_data.get('description', ''),
            alert_data.get('details', '')
        ))
        return cursor.lastrowid


def get_alerts(limit=100, alert_type=None, severity=None, resolved=None):
    """
    Retrieve alerts with optional filtering.

    Args:
        limit: Maximum number of alerts to return
        alert_type: Filter by alert type (PORT_SCAN, BRUTE_FORCE, etc.)
        severity: Filter by severity level (LOW, MEDIUM, HIGH, CRITICAL)
        resolved: Filter by resolved status (0 or 1)

    Returns:
        List of dict records from alerts table
    """
    query = 'SELECT * FROM alerts WHERE 1=1'
    params = []

    if alert_type:
        query += ' AND alert_type = ?'
        params.append(alert_type)
    if severity:
        query += ' AND severity = ?'
        params.append(severity)
    if resolved is not None:
        query += ' AND resolved = ?'
        params.append(int(resolved))

    query += ' ORDER BY id DESC LIMIT ?'
    params.append(limit)

    with get_db_connection() as conn:
        cursor = conn.execute(query, params)
        return [dict(row) for row in cursor.fetchall()]


def resolve_alert(alert_id):
    """
    Mark an alert as resolved.

    Args:
        alert_id: ID of the alert to resolve

    Returns:
        True if alert was found and resolved, False otherwise
    """
    with get_db_connection() as conn:
        cursor = conn.execute('''
            UPDATE alerts SET resolved = 1, resolved_at = ?
            WHERE id = ? AND resolved = 0
        ''', (datetime.now().isoformat(), alert_id))
        return cursor.rowcount > 0


def get_alert_counts():
    """
    Get summary counts of alerts grouped by type and severity.

    Returns:
        Dict with 'by_type' and 'by_severity' sub-dicts containing counts,
        plus 'total' and 'unresolved' counts
    """
    with get_db_connection() as conn:
        # Total and unresolved
        total = conn.execute('SELECT COUNT(*) FROM alerts').fetchone()[0]
        unresolved = conn.execute(
            'SELECT COUNT(*) FROM alerts WHERE resolved = 0'
        ).fetchone()[0]

        # By type
        type_cursor = conn.execute(
            'SELECT alert_type, COUNT(*) as cnt FROM alerts GROUP BY alert_type'
        )
        by_type = {row['alert_type']: row['cnt'] for row in type_cursor.fetchall()}

        # By severity
        sev_cursor = conn.execute(
            'SELECT severity, COUNT(*) as cnt FROM alerts GROUP BY severity'
        )
        by_severity = {row['severity']: row['cnt'] for row in sev_cursor.fetchall()}

        return {
            'total': total,
            'unresolved': unresolved,
            'by_type': by_type,
            'by_severity': by_severity
        }


# ============================================================
# ANOMALY OPERATIONS
# ============================================================
def insert_anomaly(anomaly_data):
    """
    Insert an AI anomaly detection result.

    Args:
        anomaly_data: Dict with keys: timestamp, threat_score,
                      classification, features_json, details

    Returns:
        The ID of the newly inserted anomaly record
    """
    with get_db_connection() as conn:
        cursor = conn.execute('''
            INSERT INTO anomalies
            (timestamp, threat_score, classification, features_json, details)
            VALUES (?, ?, ?, ?, ?)
        ''', (
            anomaly_data.get('timestamp', datetime.now().isoformat()),
            anomaly_data.get('threat_score', 0),
            anomaly_data.get('classification', 'Normal'),
            anomaly_data.get('features_json', '{}'),
            anomaly_data.get('details', '')
        ))
        return cursor.lastrowid


def get_recent_anomalies(limit=50):
    """
    Retrieve recent anomaly detection results.

    Args:
        limit: Maximum number of records to return

    Returns:
        List of dict records from anomalies table
    """
    with get_db_connection() as conn:
        cursor = conn.execute(
            'SELECT * FROM anomalies ORDER BY id DESC LIMIT ?', (limit,)
        )
        return [dict(row) for row in cursor.fetchall()]


def get_latest_anomaly():
    """
    Get the most recent anomaly detection result.

    Returns:
        Dict of the latest anomaly record, or None if no records exist
    """
    with get_db_connection() as conn:
        cursor = conn.execute(
            'SELECT * FROM anomalies ORDER BY id DESC LIMIT 1'
        )
        row = cursor.fetchone()
        return dict(row) if row else None


# ============================================================
# TRAFFIC STATS OPERATIONS
# ============================================================
def insert_traffic_stats(stats_data):
    """
    Insert aggregated traffic statistics snapshot.

    Args:
        stats_data: Dict with keys: timestamp, packets_per_second,
                    active_connections, total_bytes, protocol_distribution,
                    top_source_ips, top_dest_ports
    """
    with get_db_connection() as conn:
        conn.execute('''
            INSERT INTO traffic_stats
            (timestamp, packets_per_second, active_connections, total_bytes,
             protocol_distribution, top_source_ips, top_dest_ports)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        ''', (
            stats_data.get('timestamp', datetime.now().isoformat()),
            stats_data.get('packets_per_second', 0),
            stats_data.get('active_connections', 0),
            stats_data.get('total_bytes', 0),
            json.dumps(stats_data.get('protocol_distribution', {})),
            json.dumps(stats_data.get('top_source_ips', [])),
            json.dumps(stats_data.get('top_dest_ports', []))
        ))


def get_traffic_stats_history(limit=60):
    """
    Retrieve historical traffic statistics for charting.

    Args:
        limit: Number of recent snapshots to return

    Returns:
        List of dict records from traffic_stats table
    """
    with get_db_connection() as conn:
        cursor = conn.execute(
            'SELECT * FROM traffic_stats ORDER BY id DESC LIMIT ?', (limit,)
        )
        rows = [dict(row) for row in cursor.fetchall()]
        # Parse JSON fields
        for row in rows:
            try:
                row['protocol_distribution'] = json.loads(row.get('protocol_distribution', '{}'))
            except (json.JSONDecodeError, TypeError):
                row['protocol_distribution'] = {}
            try:
                row['top_source_ips'] = json.loads(row.get('top_source_ips', '[]'))
            except (json.JSONDecodeError, TypeError):
                row['top_source_ips'] = []
            try:
                row['top_dest_ports'] = json.loads(row.get('top_dest_ports', '[]'))
            except (json.JSONDecodeError, TypeError):
                row['top_dest_ports'] = []
        return list(reversed(rows))  # Chronological order


# ============================================================
# SETTINGS OPERATIONS
# ============================================================
def get_setting(key, default=None):
    """
    Retrieve a setting value by key.

    Args:
        key: Setting key string
        default: Default value if key not found

    Returns:
        Setting value string, or default if not found
    """
    with get_db_connection() as conn:
        cursor = conn.execute(
            'SELECT value FROM settings WHERE key = ?', (key,)
        )
        row = cursor.fetchone()
        return row['value'] if row else default


def set_setting(key, value):
    """
    Create or update a setting.

    Args:
        key: Setting key string
        value: Setting value string
    """
    with get_db_connection() as conn:
        conn.execute('''
            INSERT INTO settings (key, value, updated_at)
            VALUES (?, ?, ?)
            ON CONFLICT(key) DO UPDATE SET value = ?, updated_at = ?
        ''', (key, str(value), datetime.now().isoformat(),
              str(value), datetime.now().isoformat()))


# ============================================================
# DASHBOARD AGGREGATION
# ============================================================
def get_dashboard_stats():
    """
    Get aggregated statistics for the main dashboard display.

    Returns:
        Dict containing:
            - total_packets: Total number of captured packets
            - recent_packets: Packets in the last 5 minutes
            - total_alerts: Total number of alerts
            - unresolved_alerts: Number of unresolved alerts
            - alert_counts: Alerts grouped by type and severity
            - latest_anomaly: Most recent AI detection result
    """
    with get_db_connection() as conn:
        total_packets = conn.execute('SELECT COUNT(*) FROM traffic_logs').fetchone()[0]

        five_min_ago = (datetime.now() - timedelta(minutes=5)).isoformat()
        recent_packets = conn.execute(
            'SELECT COUNT(*) FROM traffic_logs WHERE timestamp >= ?',
            (five_min_ago,)
        ).fetchone()[0]

        total_alerts = conn.execute('SELECT COUNT(*) FROM alerts').fetchone()[0]
        unresolved = conn.execute(
            'SELECT COUNT(*) FROM alerts WHERE resolved = 0'
        ).fetchone()[0]

        # Latest anomaly
        anomaly_row = conn.execute(
            'SELECT * FROM anomalies ORDER BY id DESC LIMIT 1'
        ).fetchone()
        latest_anomaly = dict(anomaly_row) if anomaly_row else None

    return {
        'total_packets': total_packets,
        'recent_packets': recent_packets,
        'total_alerts': total_alerts,
        'unresolved_alerts': unresolved,
        'alert_counts': get_alert_counts(),
        'latest_anomaly': latest_anomaly
    }


# ============================================================
# REPORT QUERIES
# ============================================================
def get_report_data(hours=24):
    """
    Get comprehensive data for report generation.

    Args:
        hours: Number of hours to look back

    Returns:
        Dict containing traffic summary, alert summary, top IPs,
        and anomaly summary for the specified time period
    """
    since = (datetime.now() - timedelta(hours=hours)).isoformat()

    with get_db_connection() as conn:
        # Traffic summary
        traffic = conn.execute('''
            SELECT COUNT(*) as total_packets,
                   COALESCE(SUM(packet_size), 0) as total_bytes,
                   COUNT(DISTINCT src_ip) as unique_src_ips,
                   COUNT(DISTINCT dst_ip) as unique_dst_ips
            FROM traffic_logs WHERE timestamp >= ?
        ''', (since,)).fetchone()

        # Protocol distribution
        protocols = conn.execute('''
            SELECT protocol, COUNT(*) as count
            FROM traffic_logs WHERE timestamp >= ?
            GROUP BY protocol ORDER BY count DESC
        ''', (since,)).fetchall()

        # Alert summary
        alerts = conn.execute('''
            SELECT alert_type, severity, COUNT(*) as count
            FROM alerts WHERE timestamp >= ?
            GROUP BY alert_type, severity
            ORDER BY count DESC
        ''', (since,)).fetchall()

        # Top suspicious IPs (most alerts)
        top_ips = conn.execute('''
            SELECT source_ip, COUNT(*) as alert_count,
                   GROUP_CONCAT(DISTINCT alert_type) as alert_types
            FROM alerts WHERE timestamp >= ? AND source_ip != ''
            GROUP BY source_ip
            ORDER BY alert_count DESC LIMIT 10
        ''', (since,)).fetchall()

        # Anomaly summary
        anomalies = conn.execute('''
            SELECT classification, COUNT(*) as count,
                   AVG(threat_score) as avg_score,
                   MAX(threat_score) as max_score
            FROM anomalies WHERE timestamp >= ?
            GROUP BY classification
        ''', (since,)).fetchall()

    return {
        'period_hours': hours,
        'since': since,
        'traffic': dict(traffic) if traffic else {},
        'protocols': [dict(p) for p in protocols],
        'alerts': [dict(a) for a in alerts],
        'top_suspicious_ips': [dict(ip) for ip in top_ips],
        'anomalies': [dict(a) for a in anomalies]
    }


# ============================================================
# DATA RETENTION / CLEANUP
# ============================================================
def cleanup_old_records(days=None):
    """
    Delete records older than the specified retention period.

    Args:
        days: Number of days to retain. Uses config default if None.

    Returns:
        Dict with counts of deleted records per table
    """
    if days is None:
        days = DATA_RETENTION_DAYS

    cutoff = (datetime.now() - timedelta(days=days)).isoformat()
    deleted = {}

    with get_db_connection() as conn:
        for table in ['traffic_logs', 'alerts', 'anomalies', 'traffic_stats']:
            cursor = conn.execute(
                f'DELETE FROM {table} WHERE timestamp < ?', (cutoff,)
            )
            deleted[table] = cursor.rowcount

    logger.info('Cleanup complete: %s', deleted)
    return deleted
