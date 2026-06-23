"""
NetSight - Traffic Analyzer (MODULE 2)
=============================================
Real-time traffic statistics engine that maintains sliding windows
of packet data to compute network metrics used by the dashboard,
detection engines, and AI model.

Purpose:
    - Calculate packets per second (1s, 10s, 60s windows)
    - Track active connections (unique src+dst+port tuples)
    - Identify top source IPs by packet count
    - Identify top destination ports
    - Compute protocol distribution percentages
    - Calculate traffic volume (bytes per second)
    - Provide thread-safe statistics for real-time dashboard

Architecture:
    Receives packet_data dicts from PacketSniffer callbacks.
    Uses collections.deque with time-based windowing for efficient stats.
    Thread-safe with threading.Lock for concurrent dashboard reads.
"""

import threading
import time
import json
from datetime import datetime, timedelta
from collections import defaultdict, deque

from config import STATS_UPDATE_INTERVAL
from backend.logger import get_system_logger
from backend import database as db

logger = get_system_logger('TrafficAnalyzer')


class TrafficAnalyzer:
    """
    Real-time traffic statistics engine.

    Processes incoming packets and maintains sliding window statistics
    for dashboard display, detection engines, and AI feature extraction.

    Attributes:
        _packets_window: Time-stamped packet deque for windowed calculations
        _stats: Latest computed statistics dict
        _lock: Thread lock for safe concurrent access
    """

    def __init__(self):
        """Initialize the TrafficAnalyzer with empty tracking state."""
        # Sliding window of (timestamp, packet_data) tuples
        self._packets_window = deque(maxlen=10000)

        # Per-IP and per-port counters (reset periodically)
        self._src_ip_counts = defaultdict(int)
        self._dst_port_counts = defaultdict(int)
        self._protocol_counts = defaultdict(int)
        self._connection_set = set()  # (src_ip, dst_ip, dst_port)
        self._total_bytes = 0
        self._total_packets = 0

        # Per-IP tracking for detection modules
        self._per_ip_packet_count = defaultdict(int)
        self._per_ip_byte_count = defaultdict(int)
        self._per_ip_destinations = defaultdict(set)
        self._per_ip_ports = defaultdict(set)

        # Latest computed statistics
        self._stats = {
            'packets_per_second': 0.0,
            'packets_per_second_10s': 0.0,
            'packets_per_second_60s': 0.0,
            'active_connections': 0,
            'total_packets': 0,
            'total_bytes': 0,
            'bytes_per_second': 0.0,
            'top_source_ips': [],
            'top_dest_ports': [],
            'protocol_distribution': {},
            'unique_src_ips': 0,
            'unique_dst_ips': 0,
            'unique_ports': 0,
            'avg_packet_size': 0.0
        }

        # Historical stats for charts (last 60 snapshots)
        self._stats_history = deque(maxlen=120)

        self._lock = threading.Lock()
        self._last_cleanup = time.time()

        logger.info('TrafficAnalyzer initialized')

    def process_packet(self, packet_data):
        """
        Process an incoming packet and update all statistics.
        Called as a callback from the PacketSniffer for each captured packet.

        Args:
            packet_data: Dict with keys: timestamp, src_ip, dst_ip,
                        src_port, dst_port, protocol, packet_size, flags
        """
        now = time.time()

        with self._lock:
            # Add to sliding window
            self._packets_window.append((now, packet_data))

            # Update global counters
            self._total_packets += 1
            self._total_bytes += packet_data.get('packet_size', 0)

            src_ip = packet_data.get('src_ip', '')
            dst_ip = packet_data.get('dst_ip', '')
            dst_port = packet_data.get('dst_port')
            protocol = packet_data.get('protocol', 'OTHER')

            # Per-field counters
            self._src_ip_counts[src_ip] += 1
            if dst_port is not None:
                self._dst_port_counts[dst_port] += 1
            self._protocol_counts[protocol] += 1

            # Active connections
            if dst_port is not None:
                self._connection_set.add((src_ip, dst_ip, dst_port))

            # Per-IP tracking
            self._per_ip_packet_count[src_ip] += 1
            self._per_ip_byte_count[src_ip] += packet_data.get('packet_size', 0)
            self._per_ip_destinations[src_ip].add(dst_ip)
            if dst_port is not None:
                self._per_ip_ports[src_ip].add(dst_port)

        # Periodic cleanup of old window data
        if now - self._last_cleanup > 5:
            self._cleanup_window(now)
            self._last_cleanup = now

    def compute_stats(self):
        """
        Compute all traffic statistics from the current sliding window.
        Called periodically by the main app's background scheduler.

        Returns:
            Dict containing all computed statistics
        """
        now = time.time()

        with self._lock:
            # --- Packets per second (multiple windows) ---
            pps_1s = self._count_packets_in_window(now, 1)
            pps_10s = self._count_packets_in_window(now, 10) / 10.0
            pps_60s = self._count_packets_in_window(now, 60) / 60.0

            # --- Bytes per second ---
            bytes_10s = self._sum_bytes_in_window(now, 10) / 10.0

            # --- Active connections ---
            active_connections = len(self._connection_set)

            # --- Top source IPs (by packet count) ---
            top_src = sorted(
                self._src_ip_counts.items(),
                key=lambda x: x[1], reverse=True
            )[:10]

            # --- Top destination ports ---
            top_ports = sorted(
                self._dst_port_counts.items(),
                key=lambda x: x[1], reverse=True
            )[:10]

            # --- Protocol distribution ---
            total_proto = sum(self._protocol_counts.values()) or 1
            proto_dist = {
                proto: round(count / total_proto * 100, 1)
                for proto, count in sorted(
                    self._protocol_counts.items(),
                    key=lambda x: x[1], reverse=True
                )
            }

            # --- Averages ---
            avg_size = self._total_bytes / max(self._total_packets, 1)

            # --- Unique counts ---
            unique_src = len(self._src_ip_counts)
            unique_dst = len(set(
                p.get('dst_ip', '') for _, p in self._packets_window
            ))
            unique_ports = len(self._dst_port_counts)

            # Update stats
            self._stats = {
                'packets_per_second': round(pps_1s, 1),
                'packets_per_second_10s': round(pps_10s, 1),
                'packets_per_second_60s': round(pps_60s, 1),
                'active_connections': active_connections,
                'total_packets': self._total_packets,
                'total_bytes': self._total_bytes,
                'bytes_per_second': round(bytes_10s, 1),
                'top_source_ips': [
                    {'ip': ip, 'count': count} for ip, count in top_src
                ],
                'top_dest_ports': [
                    {'port': port, 'count': count} for port, count in top_ports
                ],
                'protocol_distribution': proto_dist,
                'unique_src_ips': unique_src,
                'unique_dst_ips': unique_dst,
                'unique_ports': unique_ports,
                'avg_packet_size': round(avg_size, 1),
                'timestamp': datetime.now().isoformat()
            }

            # Add to history
            self._stats_history.append(dict(self._stats))

        return self._stats

    def get_stats(self):
        """
        Get the latest computed statistics.
        Thread-safe for concurrent dashboard reads.

        Returns:
            Dict containing all current traffic statistics
        """
        with self._lock:
            return dict(self._stats)

    def get_stats_history(self, limit=60):
        """
        Get historical statistics for charting.

        Args:
            limit: Number of recent snapshots to return

        Returns:
            List of stats dicts in chronological order
        """
        with self._lock:
            history = list(self._stats_history)
            return history[-limit:]

    def get_per_ip_stats(self, ip_address):
        """
        Get statistics for a specific IP address.

        Args:
            ip_address: IP address to query

        Returns:
            Dict with per-IP statistics
        """
        with self._lock:
            return {
                'ip': ip_address,
                'packet_count': self._per_ip_packet_count.get(ip_address, 0),
                'byte_count': self._per_ip_byte_count.get(ip_address, 0),
                'unique_destinations': len(self._per_ip_destinations.get(ip_address, set())),
                'unique_ports': len(self._per_ip_ports.get(ip_address, set()))
            }

    def get_ai_features(self):
        """
        Extract features for the AI anomaly detection model.

        Returns:
            Dict with features: packet_rate, connection_rate,
            unique_ip_count, unique_port_count, avg_packet_size
        """
        now = time.time()

        with self._lock:
            # Compute features from the last 60 seconds
            window_packets = [
                p for ts, p in self._packets_window
                if now - ts <= 60
            ]

            packet_count = len(window_packets)
            packet_rate = packet_count / 60.0

            # Connection rate: unique (src, dst, port) tuples in window
            connections = set()
            ips = set()
            ports = set()
            total_size = 0

            for p in window_packets:
                src = p.get('src_ip', '')
                dst = p.get('dst_ip', '')
                dp = p.get('dst_port')
                ips.add(src)
                ips.add(dst)
                if dp is not None:
                    ports.add(dp)
                    connections.add((src, dst, dp))
                total_size += p.get('packet_size', 0)

            connection_rate = len(connections) / 60.0
            avg_size = total_size / max(packet_count, 1)

            return {
                'packet_rate': round(packet_rate, 2),
                'connection_rate': round(connection_rate, 2),
                'unique_ip_count': len(ips),
                'unique_port_count': len(ports),
                'avg_packet_size': round(avg_size, 2)
            }

    def save_stats_snapshot(self):
        """
        Save current statistics to the database for historical tracking.
        Called periodically by the background scheduler.
        """
        stats = self.get_stats()
        try:
            db.insert_traffic_stats({
                'timestamp': datetime.now().isoformat(),
                'packets_per_second': stats.get('packets_per_second', 0),
                'active_connections': stats.get('active_connections', 0),
                'total_bytes': stats.get('total_bytes', 0),
                'protocol_distribution': stats.get('protocol_distribution', {}),
                'top_source_ips': stats.get('top_source_ips', []),
                'top_dest_ports': stats.get('top_dest_ports', [])
            })
        except Exception as e:
            logger.error('Failed to save stats snapshot: %s', str(e))

    # ============================================================
    # INTERNAL HELPERS
    # ============================================================
    def _count_packets_in_window(self, now, seconds):
        """Count packets within the last N seconds."""
        cutoff = now - seconds
        return sum(1 for ts, _ in self._packets_window if ts >= cutoff)

    def _sum_bytes_in_window(self, now, seconds):
        """Sum packet bytes within the last N seconds."""
        cutoff = now - seconds
        return sum(
            p.get('packet_size', 0)
            for ts, p in self._packets_window
            if ts >= cutoff
        )

    def _cleanup_window(self, now):
        """Remove packets older than 120 seconds from the window."""
        cutoff = now - 120
        while self._packets_window and self._packets_window[0][0] < cutoff:
            self._packets_window.popleft()
