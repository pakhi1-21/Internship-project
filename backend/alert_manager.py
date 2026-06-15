"""
NetSight - Alert Management System (MODULE 7)
====================================================
Centralized alert creation, deduplication, storage, and retrieval.
All detection modules route their alerts through this manager to ensure
consistent formatting, severity classification, and dedup logic.

Purpose:
    - Create and store security alerts from all detection modules
    - Deduplicate alerts (suppress repeats within configurable window)
    - Classify alert severity (LOW, MEDIUM, HIGH, CRITICAL)
    - Track alert types (PORT_SCAN, BRUTE_FORCE, TRAFFIC_SPIKE, AI_ANOMALY, SUSPICIOUS_ACTIVITY)
    - Provide alert query and resolution functions
    - Trigger email notifications for HIGH/CRITICAL alerts
    - Log all alerts to alerts.log

Severity Levels:
    LOW      - Informational, minor anomaly detected
    MEDIUM   - Notable activity, warrants monitoring
    HIGH     - Significant threat, immediate attention recommended
    CRITICAL - Active attack, immediate response required

Alert Types:
    PORT_SCAN           - Port scanning activity detected
    BRUTE_FORCE         - Brute force login/connection attempts
    TRAFFIC_SPIKE       - Unusual traffic volume spike
    AI_ANOMALY          - AI/ML-detected anomalous behavior
    SUSPICIOUS_ACTIVITY - General suspicious traffic patterns
"""

import threading
from datetime import datetime, timedelta
from collections import defaultdict

from config import (
    ALERT_DEDUP_WINDOW, SEVERITY_LOW, SEVERITY_MEDIUM,
    SEVERITY_HIGH, SEVERITY_CRITICAL, ALERT_PORT_SCAN,
    ALERT_BRUTE_FORCE, ALERT_TRAFFIC_SPIKE, ALERT_AI_ANOMALY,
    ALERT_SUSPICIOUS, EMAIL_ENABLED
)
from backend.logger import get_alert_logger, get_system_logger
from backend import database as db

alert_logger = get_alert_logger('AlertManager')
system_logger = get_system_logger('AlertManager')


class AlertManager:
    """
    Centralized alert management system.

    Handles creation, deduplication, storage, and notification of
    security alerts from all detection modules.

    Attributes:
        _recent_alerts: Dict tracking recent alerts for deduplication
        _lock: Thread lock for safe concurrent access
        _alert_callbacks: List of callback functions triggered on new alerts
    """

    def __init__(self):
        """Initialize the AlertManager with empty tracking state."""
        self._recent_alerts = defaultdict(list)  # key: (alert_type, source_ip) -> [timestamps]
        self._lock = threading.Lock()
        self._alert_callbacks = []
        self._stats = {
            'total_created': 0,
            'total_deduplicated': 0,
            'by_type': defaultdict(int),
            'by_severity': defaultdict(int)
        }
        system_logger.info('AlertManager initialized')

    def register_callback(self, callback):
        """
        Register a callback function to be called when a new alert is created.
        Used for real-time dashboard updates and email notifications.

        Args:
            callback: Function accepting (alert_data: dict) as argument
        """
        self._alert_callbacks.append(callback)

    def create_alert(self, alert_type, severity, source_ip, description,
                     destination_ip='', details=''):
        """
        Create a new security alert with deduplication.

        If an alert with the same type and source IP was created within
        the dedup window (default 5 minutes), the alert is suppressed
        to prevent flooding.

        Args:
            alert_type: One of PORT_SCAN, BRUTE_FORCE, TRAFFIC_SPIKE,
                        AI_ANOMALY, SUSPICIOUS_ACTIVITY
            severity: One of LOW, MEDIUM, HIGH, CRITICAL
            source_ip: IP address of the alert source
            description: Human-readable alert description
            destination_ip: Target IP (optional)
            details: Additional details string (optional)

        Returns:
            Dict of alert data if created, None if deduplicated
        """
        with self._lock:
            # --- Deduplication check ---
            dedup_key = (alert_type, source_ip)
            now = datetime.now()
            cutoff = now - timedelta(seconds=ALERT_DEDUP_WINDOW)

            # Clean old entries and check for recent duplicates
            self._recent_alerts[dedup_key] = [
                ts for ts in self._recent_alerts[dedup_key]
                if ts > cutoff
            ]

            if self._recent_alerts[dedup_key]:
                self._stats['total_deduplicated'] += 1
                return None  # Suppressed duplicate

            # Record this alert for future dedup
            self._recent_alerts[dedup_key].append(now)

            # --- Build alert data ---
            alert_data = {
                'timestamp': now.isoformat(),
                'alert_type': alert_type,
                'severity': severity,
                'source_ip': source_ip,
                'destination_ip': destination_ip,
                'description': description,
                'details': details
            }

            # --- Store in database ---
            try:
                alert_id = db.insert_alert(alert_data)
                alert_data['id'] = alert_id
            except Exception as e:
                system_logger.error('Failed to store alert: %s', str(e))

            # --- Log the alert ---
            log_level = self._severity_to_log_level(severity)
            log_func = getattr(alert_logger, log_level, alert_logger.warning)
            log_func(
                '[%s] [%s] %s | Source: %s | Dest: %s | %s',
                alert_type, severity, description,
                source_ip, destination_ip, details
            )

            # --- Update stats ---
            self._stats['total_created'] += 1
            self._stats['by_type'][alert_type] += 1
            self._stats['by_severity'][severity] += 1

            # --- Trigger callbacks ---
            for callback in self._alert_callbacks:
                try:
                    callback(alert_data)
                except Exception as e:
                    system_logger.error('Alert callback error: %s', str(e))

            # --- Email notification for HIGH/CRITICAL ---
            if severity in (SEVERITY_HIGH, SEVERITY_CRITICAL) and EMAIL_ENABLED:
                self._send_email_notification(alert_data)

            return alert_data

    def create_port_scan_alert(self, source_ip, ports_scanned, scan_type='Fast Scan',
                               destination_ip=''):
        """
        Create a port scan detection alert.

        Automatically determines severity based on the number of ports scanned.

        Args:
            source_ip: IP address performing the scan
            ports_scanned: Number of unique ports scanned
            scan_type: Type of scan (SYN Scan, Fast Scan, Sequential Scan)
            destination_ip: Target IP being scanned

        Returns:
            Dict of alert data if created, None if deduplicated
        """
        if ports_scanned > 100:
            severity = SEVERITY_CRITICAL
        elif ports_scanned > 50:
            severity = SEVERITY_HIGH
        elif ports_scanned > 25:
            severity = SEVERITY_MEDIUM
        else:
            severity = SEVERITY_LOW

        description = f'{scan_type} detected: {ports_scanned} ports scanned'
        details = f'Scan type: {scan_type}, Ports scanned: {ports_scanned}'

        return self.create_alert(
            ALERT_PORT_SCAN, severity, source_ip, description,
            destination_ip, details
        )

    def create_brute_force_alert(self, source_ip, attempt_count, service_name,
                                  destination_ip='', destination_port=0):
        """
        Create a brute force detection alert.

        Automatically determines severity based on the number of attempts.

        Args:
            source_ip: IP address making the attempts
            attempt_count: Number of connection attempts
            service_name: Name of the targeted service (SSH, RDP, etc.)
            destination_ip: Target IP
            destination_port: Target port number

        Returns:
            Dict of alert data if created, None if deduplicated
        """
        if attempt_count > 100:
            severity = SEVERITY_CRITICAL
        elif attempt_count > 50:
            severity = SEVERITY_HIGH
        elif attempt_count > 20:
            severity = SEVERITY_MEDIUM
        else:
            severity = SEVERITY_LOW

        description = (
            f'Brute force on {service_name} (port {destination_port}): '
            f'{attempt_count} attempts'
        )
        details = (
            f'Service: {service_name}, Port: {destination_port}, '
            f'Attempts: {attempt_count}'
        )

        return self.create_alert(
            ALERT_BRUTE_FORCE, severity, source_ip, description,
            destination_ip, details
        )

    def create_traffic_spike_alert(self, source_ip, current_rate, normal_rate,
                                    multiplier):
        """
        Create a traffic spike alert.

        Args:
            source_ip: IP address generating the spike (or 'NETWORK' for global)
            current_rate: Current packets per second
            normal_rate: Normal/expected packets per second
            multiplier: How many times above normal

        Returns:
            Dict of alert data if created, None if deduplicated
        """
        if multiplier > 10:
            severity = SEVERITY_CRITICAL
        elif multiplier > 5:
            severity = SEVERITY_HIGH
        elif multiplier > 3:
            severity = SEVERITY_MEDIUM
        else:
            severity = SEVERITY_LOW

        description = (
            f'Traffic spike: {current_rate:.1f} pps '
            f'({multiplier:.1f}x normal rate of {normal_rate:.1f} pps)'
        )
        details = (
            f'Current rate: {current_rate:.1f} pps, '
            f'Normal rate: {normal_rate:.1f} pps, '
            f'Multiplier: {multiplier:.1f}x'
        )

        return self.create_alert(
            ALERT_TRAFFIC_SPIKE, severity, source_ip, description,
            details=details
        )

    def create_ai_anomaly_alert(self, source_ip, threat_score, classification,
                                 details=''):
        """
        Create an AI anomaly detection alert.

        Args:
            source_ip: Related IP address (or 'AI_ENGINE' for general)
            threat_score: Computed threat score (0-100)
            classification: 'Suspicious' or 'Malicious'
            details: Additional context from AI engine

        Returns:
            Dict of alert data if created, None if deduplicated
        """
        if threat_score > 85:
            severity = SEVERITY_CRITICAL
        elif threat_score > 70:
            severity = SEVERITY_HIGH
        elif threat_score > 50:
            severity = SEVERITY_MEDIUM
        else:
            severity = SEVERITY_LOW

        description = (
            f'AI anomaly detected: {classification} '
            f'(threat score: {threat_score:.1f})'
        )

        return self.create_alert(
            ALERT_AI_ANOMALY, severity, source_ip, description,
            details=details
        )

    def create_suspicious_activity_alert(self, source_ip, activity_type,
                                          threat_score, details=''):
        """
        Create a suspicious activity alert.

        Args:
            source_ip: IP address exhibiting suspicious behavior
            activity_type: Type of suspicious activity detected
            threat_score: Computed threat score (0-100)
            details: Additional context

        Returns:
            Dict of alert data if created, None if deduplicated
        """
        if threat_score > 80:
            severity = SEVERITY_HIGH
        elif threat_score > 50:
            severity = SEVERITY_MEDIUM
        else:
            severity = SEVERITY_LOW

        description = f'Suspicious activity: {activity_type} (score: {threat_score:.1f})'

        return self.create_alert(
            ALERT_SUSPICIOUS, severity, source_ip, description,
            details=details
        )

    def get_stats(self):
        """
        Get alert manager statistics.

        Returns:
            Dict with total_created, total_deduplicated, by_type, and by_severity counts
        """
        with self._lock:
            return {
                'total_created': self._stats['total_created'],
                'total_deduplicated': self._stats['total_deduplicated'],
                'by_type': dict(self._stats['by_type']),
                'by_severity': dict(self._stats['by_severity'])
            }

    def cleanup_dedup_cache(self):
        """Remove expired entries from the deduplication cache."""
        with self._lock:
            cutoff = datetime.now() - timedelta(seconds=ALERT_DEDUP_WINDOW)
            expired_keys = []
            for key, timestamps in self._recent_alerts.items():
                self._recent_alerts[key] = [
                    ts for ts in timestamps if ts > cutoff
                ]
                if not self._recent_alerts[key]:
                    expired_keys.append(key)
            for key in expired_keys:
                del self._recent_alerts[key]

    @staticmethod
    def _severity_to_log_level(severity):
        """
        Map alert severity to Python logging level name.

        Args:
            severity: Severity string

        Returns:
            Lowercase logging level name
        """
        mapping = {
            SEVERITY_LOW: 'info',
            SEVERITY_MEDIUM: 'warning',
            SEVERITY_HIGH: 'error',
            SEVERITY_CRITICAL: 'critical'
        }
        return mapping.get(severity, 'warning')

    def _send_email_notification(self, alert_data):
        """
        Send email notification for high-severity alerts.
        Delegates to the email_alerts module.

        Args:
            alert_data: Dict containing alert details
        """
        try:
            from backend.email_alerts import send_alert_email
            send_alert_email(alert_data)
        except ImportError:
            system_logger.warning('Email alerts module not available')
        except Exception as e:
            system_logger.error('Failed to send email notification: %s', str(e))


# ============================================================
# SINGLETON INSTANCE
# ============================================================
# Global alert manager instance shared across all modules
alert_manager = AlertManager()
