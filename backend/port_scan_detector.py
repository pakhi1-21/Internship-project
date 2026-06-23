"""
NetSight - Port Scan Detection (MODULE 3)
=================================================
Detects port scanning attacks by tracking the number of unique
destination ports accessed by each source IP within a time window.

Purpose:
    - Detect SYN scans (SYN flag set but no completed handshake)
    - Detect fast port scans (many ports in short time)
    - Detect sequential port scans (ports accessed in order)
    - Generate alerts via AlertManager with severity based on port count
    - Automatic cleanup of expired tracking data

Detection Logic:
    1. Track unique destination ports per source IP within a sliding window
    2. If unique port count exceeds threshold → generate alert
    3. SYN scan: Check for SYN-only flags (no ACK)
    4. Sequential scan: Check if ports are numerically sequential
    5. Cooldown period prevents alert flooding for the same IP

Data Stored per Alert:
    - Attacker IP
    - Number of ports scanned
    - Scan type (SYN, Fast, Sequential)
    - Time detected
"""

import threading
import time
from datetime import datetime
from collections import defaultdict

from config import (
    PORT_SCAN_THRESHOLD, PORT_SCAN_TIME_WINDOW,
    PORT_SCAN_SYN_ONLY, PORT_SCAN_SEQUENTIAL_GAP
)
from backend.logger import get_system_logger
from backend.alert_manager import alert_manager

logger = get_system_logger('PortScanDetector')


class PortScanDetector:
    """
    Detects port scanning attacks by monitoring destination port access patterns.

    Tracks per-IP port access history within a configurable time window
    and raises alerts when thresholds are exceeded.

    Attributes:
        _port_access: Dict mapping src_ip → list of (timestamp, port, flags) tuples
        _alerted_ips: Dict mapping src_ip → last alert timestamp (for cooldown)
        _lock: Thread lock for concurrent access safety
    """

    def __init__(self):
        """Initialize the PortScanDetector with empty tracking state."""
        # src_ip → [(timestamp, dst_port, flags), ...]
        self._port_access = defaultdict(list)

        # src_ip → last alert time (to prevent flooding)
        self._alerted_ips = {}

        self._lock = threading.Lock()
        self._stats = {
            'total_scans_detected': 0,
            'syn_scans': 0,
            'fast_scans': 0,
            'sequential_scans': 0,
            'active_trackers': 0
        }

        logger.info(
            'PortScanDetector initialized (threshold: %d ports in %ds)',
            PORT_SCAN_THRESHOLD, PORT_SCAN_TIME_WINDOW
        )

    def process_packet(self, packet_data):
        """
        Process a packet and check for port scan patterns.
        Called as a callback from the PacketSniffer.

        Args:
            packet_data: Dict with keys: src_ip, dst_ip, dst_port,
                        protocol, flags, timestamp
        """
        # Only track TCP and UDP with destination ports
        dst_port = packet_data.get('dst_port')
        if dst_port is None:
            return

        src_ip = packet_data.get('src_ip', '')
        if not src_ip:
            return

        flags = packet_data.get('flags', '')
        now = time.time()

        with self._lock:
            # Add port access record
            self._port_access[src_ip].append((now, dst_port, flags))

            # Cleanup old entries for this IP
            cutoff = now - PORT_SCAN_TIME_WINDOW
            self._port_access[src_ip] = [
                (ts, port, f) for ts, port, f in self._port_access[src_ip]
                if ts >= cutoff
            ]

            # Get unique ports accessed in window
            entries = self._port_access[src_ip]
            unique_ports = set(port for _, port, _ in entries)

            # Check if threshold exceeded
            if len(unique_ports) >= PORT_SCAN_THRESHOLD:
                self._check_and_alert(src_ip, entries, unique_ports, now,
                                       packet_data.get('dst_ip', ''))

    def _check_and_alert(self, src_ip, entries, unique_ports, now, dst_ip):
        """
        Check scan type and generate an alert if cooldown allows.

        Args:
            src_ip: Source IP performing the scan
            entries: List of (timestamp, port, flags) tuples
            unique_ports: Set of unique destination ports
            now: Current timestamp
            dst_ip: Destination IP being scanned
        """
        # Check cooldown (don't re-alert same IP within dedup window)
        last_alert = self._alerted_ips.get(src_ip, 0)
        if now - last_alert < PORT_SCAN_TIME_WINDOW * 3:
            return

        # Determine scan type
        scan_type = self._classify_scan(entries, unique_ports)

        # Generate alert
        alert = alert_manager.create_port_scan_alert(
            source_ip=src_ip,
            ports_scanned=len(unique_ports),
            scan_type=scan_type,
            destination_ip=dst_ip
        )

        if alert:
            self._alerted_ips[src_ip] = now
            self._stats['total_scans_detected'] += 1

            if scan_type == 'SYN Scan':
                self._stats['syn_scans'] += 1
            elif scan_type == 'Sequential Scan':
                self._stats['sequential_scans'] += 1
            else:
                self._stats['fast_scans'] += 1

            logger.warning(
                'Port scan detected: %s scanned %d ports (%s)',
                src_ip, len(unique_ports), scan_type
            )

        # Clear tracking for this IP after alert
        self._port_access[src_ip] = []

    def _classify_scan(self, entries, unique_ports):
        """
        Classify the type of port scan based on packet characteristics.

        Args:
            entries: List of (timestamp, port, flags) tuples
            unique_ports: Set of unique destination ports

        Returns:
            String: 'SYN Scan', 'Sequential Scan', or 'Fast Scan'
        """
        # Check for SYN scan: majority of packets have SYN-only flags
        if PORT_SCAN_SYN_ONLY:
            syn_only_count = sum(
                1 for _, _, flags in entries
                if 'S' in flags and 'A' not in flags
            )
            if syn_only_count > len(entries) * 0.7:
                return 'SYN Scan'

        # Check for sequential scan: ports are in numeric order
        if self._is_sequential(unique_ports):
            return 'Sequential Scan'

        return 'Fast Scan'

    @staticmethod
    def _is_sequential(ports):
        """
        Determine if a set of ports is accessed in sequential order.
        Uses median gap analysis: sequential if median gap between
        sorted ports is small.

        Args:
            ports: Set of port numbers

        Returns:
            True if the ports appear to be sequential
        """
        if len(ports) < 5:
            return False

        sorted_ports = sorted(ports)
        gaps = [
            sorted_ports[i + 1] - sorted_ports[i]
            for i in range(len(sorted_ports) - 1)
        ]
        gaps.sort()
        median_gap = gaps[len(gaps) // 2]
        return median_gap <= PORT_SCAN_SEQUENTIAL_GAP

    def get_stats(self):
        """
        Get port scan detection statistics.

        Returns:
            Dict with detection counts and active tracker count
        """
        with self._lock:
            self._stats['active_trackers'] = len(self._port_access)
            return dict(self._stats)

    def cleanup(self):
        """
        Remove expired tracking data and old cooldown entries.
        Should be called periodically by the background scheduler.
        """
        now = time.time()
        cutoff = now - PORT_SCAN_TIME_WINDOW

        with self._lock:
            # Clean port access records
            expired_ips = []
            for ip in list(self._port_access.keys()):
                self._port_access[ip] = [
                    (ts, port, f) for ts, port, f in self._port_access[ip]
                    if ts >= cutoff
                ]
                if not self._port_access[ip]:
                    expired_ips.append(ip)

            for ip in expired_ips:
                del self._port_access[ip]

            # Clean alerted IPs cooldown
            alert_cutoff = now - PORT_SCAN_TIME_WINDOW * 6
            self._alerted_ips = {
                ip: ts for ip, ts in self._alerted_ips.items()
                if ts > alert_cutoff
            }
