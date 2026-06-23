"""
NetSight - Brute Force Detection (MODULE 4)
===================================================
Detects brute force login and connection attempts by monitoring
repeated connections to authentication service ports.

Purpose:
    - Detect repeated login attempts (SSH, RDP, FTP, etc.)
    - Detect excessive connection attempts to single service
    - Generate alerts based on attempt thresholds
    - Track per-IP, per-service attempt counts
    - Cooldown period prevents alert flooding

Detection Logic:
    1. Monitor connection attempts to known service ports (SSH:22, RDP:3389, etc.)
    2. Track connection count per (source_ip, destination_port) pair
    3. If attempts exceed threshold within time window → generate alert
    4. RST/RA flags indicate failed connections (stronger indicator)
    5. Cooldown prevents duplicate alerts for same IP+service combo

Data Stored per Alert:
    - Source IP
    - Attempt count
    - Target service name and port
    - Detection time
"""

import threading
import time
from datetime import datetime
from collections import defaultdict

from config import (
    BRUTE_FORCE_THRESHOLD, BRUTE_FORCE_TIME_WINDOW,
    BRUTE_FORCE_COOLDOWN, BRUTE_FORCE_PORTS
)
from backend.logger import get_system_logger
from backend.alert_manager import alert_manager

logger = get_system_logger('BruteForceDetector')


class BruteForceDetector:
    """
    Detects brute force attacks by monitoring repeated connection attempts
    to authentication services.

    Tracks per-IP connection attempts to service ports and generates
    alerts when attempt thresholds are exceeded within a time window.

    Attributes:
        _connection_attempts: Dict mapping (src_ip, dst_port) → [timestamps]
        _failed_attempts: Dict mapping (src_ip, dst_port) → count of RST flags
        _alerted: Dict mapping (src_ip, dst_port) → last alert timestamp
        _lock: Thread lock for concurrent access safety
    """

    def __init__(self):
        """Initialize the BruteForceDetector with empty tracking state."""
        # (src_ip, dst_port) → [timestamp, ...]
        self._connection_attempts = defaultdict(list)

        # (src_ip, dst_port) → count of failed (RST) connections
        self._failed_attempts = defaultdict(int)

        # (src_ip, dst_port) → last alert timestamp (cooldown tracking)
        self._alerted = {}

        self._lock = threading.Lock()
        self._stats = {
            'total_attacks_detected': 0,
            'active_trackers': 0,
            'services_targeted': defaultdict(int)
        }

        logger.info(
            'BruteForceDetector initialized (threshold: %d attempts in %ds, '
            'monitoring %d service ports)',
            BRUTE_FORCE_THRESHOLD, BRUTE_FORCE_TIME_WINDOW,
            len(BRUTE_FORCE_PORTS)
        )

    def process_packet(self, packet_data):
        """
        Process a packet and check for brute force patterns.
        Called as a callback from the PacketSniffer.

        Only processes TCP packets directed at monitored service ports.

        Args:
            packet_data: Dict with keys: src_ip, dst_ip, dst_port,
                        protocol, flags, timestamp
        """
        # Only monitor TCP connections to known service ports
        if packet_data.get('protocol') != 'TCP':
            return

        dst_port = packet_data.get('dst_port')
        if dst_port is None or dst_port not in BRUTE_FORCE_PORTS:
            return

        src_ip = packet_data.get('src_ip', '')
        if not src_ip:
            return

        flags = packet_data.get('flags', '')
        now = time.time()
        key = (src_ip, dst_port)

        with self._lock:
            # Track SYN packets (connection initiation) and all connection attempts
            if 'S' in flags:
                self._connection_attempts[key].append(now)

            # Track failed connections (RST flag indicates rejection)
            if 'R' in flags:
                self._failed_attempts[key] += 1

            # Cleanup old entries for this key
            cutoff = now - BRUTE_FORCE_TIME_WINDOW
            self._connection_attempts[key] = [
                ts for ts in self._connection_attempts[key]
                if ts >= cutoff
            ]

            # Check if threshold exceeded
            attempt_count = len(self._connection_attempts[key])
            if attempt_count >= BRUTE_FORCE_THRESHOLD:
                self._check_and_alert(
                    src_ip, dst_port, attempt_count, now,
                    packet_data.get('dst_ip', '')
                )

    def _check_and_alert(self, src_ip, dst_port, attempt_count, now, dst_ip):
        """
        Check cooldown and generate brute force alert if appropriate.

        Args:
            src_ip: Source IP making the attempts
            dst_port: Target service port
            attempt_count: Number of connection attempts in window
            now: Current timestamp
            dst_ip: Destination IP being targeted
        """
        key = (src_ip, dst_port)

        # Check cooldown
        last_alert = self._alerted.get(key, 0)
        if now - last_alert < BRUTE_FORCE_COOLDOWN:
            return

        service_name = BRUTE_FORCE_PORTS.get(dst_port, f'Port-{dst_port}')

        # Generate alert
        alert = alert_manager.create_brute_force_alert(
            source_ip=src_ip,
            attempt_count=attempt_count,
            service_name=service_name,
            destination_ip=dst_ip,
            destination_port=dst_port
        )

        if alert:
            self._alerted[key] = now
            self._stats['total_attacks_detected'] += 1
            self._stats['services_targeted'][service_name] += 1

            failed = self._failed_attempts.get(key, 0)
            logger.warning(
                'Brute force detected: %s → %s:%d (%s) — %d attempts '
                '(%d failed) in %ds',
                src_ip, dst_ip, dst_port, service_name,
                attempt_count, failed, BRUTE_FORCE_TIME_WINDOW
            )

        # Reset counter for this key after alerting
        self._connection_attempts[key] = []
        self._failed_attempts[key] = 0

    def get_stats(self):
        """
        Get brute force detection statistics.

        Returns:
            Dict with detection counts, active trackers, and targeted services
        """
        with self._lock:
            self._stats['active_trackers'] = len(self._connection_attempts)
            stats = dict(self._stats)
            stats['services_targeted'] = dict(self._stats['services_targeted'])
            return stats

    def cleanup(self):
        """
        Remove expired tracking data and old cooldown entries.
        Should be called periodically by the background scheduler.
        """
        now = time.time()
        cutoff = now - BRUTE_FORCE_TIME_WINDOW

        with self._lock:
            # Clean connection attempt records
            expired_keys = []
            for key in list(self._connection_attempts.keys()):
                self._connection_attempts[key] = [
                    ts for ts in self._connection_attempts[key]
                    if ts >= cutoff
                ]
                if not self._connection_attempts[key]:
                    expired_keys.append(key)

            for key in expired_keys:
                del self._connection_attempts[key]
                self._failed_attempts.pop(key, None)

            # Clean cooldown records
            cooldown_cutoff = now - BRUTE_FORCE_COOLDOWN * 2
            self._alerted = {
                key: ts for key, ts in self._alerted.items()
                if ts > cooldown_cutoff
            }
