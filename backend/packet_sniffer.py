"""
NetSight - Packet Capture Engine (MODULE 1)
==================================================
Captures live network packets using Scapy's AsyncSniffer, extracts
protocol fields, and feeds data into the analysis pipeline. Includes
a simulation mode for environments without Npcap/WinPcap.

Purpose:
    - Capture live packets on the network interface
    - Support TCP, UDP, and ICMP protocols
    - Extract: Source IP, Destination IP, Source Port, Destination Port,
      Protocol, Packet Size, Timestamp, TCP Flags
    - Queue packets for batch database storage
    - Provide start/stop/status control API
    - Fallback to simulation mode when Npcap unavailable

Architecture:
    AsyncSniffer → prn callback (minimal) → Queue → Worker thread → batch DB insert
"""

import threading
import queue
import time
import random
from datetime import datetime
from collections import deque

from config import (
    CAPTURE_INTERFACE, CAPTURE_FILTER, PACKET_BATCH_SIZE,
    PACKET_BATCH_TIMEOUT, SIMULATION_MODE, SIMULATION_PPS
)
from backend.logger import get_system_logger
from backend import database as db

logger = get_system_logger('PacketSniffer')

# Check if Scapy is available with packet capture support
SCAPY_AVAILABLE = False
try:
    from scapy.all import AsyncSniffer, IP, TCP, UDP, ICMP, conf
    # Test if Npcap/WinPcap is actually usable on Windows
    try:
        # Accessing L2socket forces Scapy to check for pcap provider
        _ = conf.L2socket
        SCAPY_AVAILABLE = True
    except Exception:
        SCAPY_AVAILABLE = False
except ImportError:
    SCAPY_AVAILABLE = False

if not SCAPY_AVAILABLE:
    logger.warning('Npcap not available - using simulation mode for traffic generation')


class PacketSniffer:
    """
    Network packet capture engine with live and simulation modes.

    In live mode, uses Scapy AsyncSniffer to capture real network packets.
    In simulation mode, generates realistic synthetic traffic for demonstration.

    Attributes:
        _sniffer: Scapy AsyncSniffer instance (live mode only)
        _packet_queue: Thread-safe queue for captured packets
        _worker_thread: Background thread for processing queued packets
        _running: Flag indicating if capture is active
        _packet_buffer: Buffer for batch database inserts
        _stats: Real-time capture statistics
    """

    def __init__(self):
        """Initialize the PacketSniffer with default state."""
        self._sniffer = None
        self._packet_queue = queue.Queue(maxsize=10000)
        self._worker_thread = None
        self._sim_thread = None
        self._running = False
        self._packet_buffer = []
        self._last_flush_time = time.time()
        self._lock = threading.Lock()

        # Capture statistics
        self._stats = {
            'status': 'stopped',
            'mode': 'simulation' if (SIMULATION_MODE or not SCAPY_AVAILABLE) else 'live',
            'packets_captured': 0,
            'packets_processed': 0,
            'packets_dropped': 0,
            'start_time': None,
            'interface': CAPTURE_INTERFACE or 'auto',
            'filter': CAPTURE_FILTER
        }

        # Recent packets for real-time display (last 200)
        self._recent_packets = deque(maxlen=200)

        # Callbacks for real-time packet processing (detectors)
        self._packet_callbacks = []

        logger.info('PacketSniffer initialized (mode: %s)', self._stats['mode'])

    def register_callback(self, callback):
        """
        Register a callback for real-time packet processing.
        Detection engines register here to receive packets as they arrive.

        Args:
            callback: Function accepting (packet_data: dict) as argument
        """
        self._packet_callbacks.append(callback)

    def start_capture(self):
        """
        Start packet capture.

        In live mode, starts AsyncSniffer on the configured interface.
        In simulation mode, starts generating synthetic packets.
        Starts the worker thread for batch processing.

        Returns:
            Dict with capture status information
        """
        if self._running:
            logger.warning('Capture already running')
            return self._stats

        self._running = True
        self._stats['status'] = 'running'
        self._stats['start_time'] = datetime.now().isoformat()

        # Start worker thread for processing packets from queue
        self._worker_thread = threading.Thread(
            target=self._process_queue, daemon=True, name='PacketWorker'
        )
        self._worker_thread.start()

        if self._stats['mode'] == 'live' and SCAPY_AVAILABLE:
            self._start_live_capture()
        else:
            self._start_simulation()

        logger.info('Packet capture started (mode: %s)', self._stats['mode'])
        return self._stats

    def stop_capture(self):
        """
        Stop packet capture and flush remaining packets.

        Returns:
            Dict with final capture statistics
        """
        if not self._running:
            return self._stats

        self._running = False
        self._stats['status'] = 'stopped'

        # Stop live sniffer
        if self._sniffer:
            try:
                self._sniffer.stop()
            except Exception as e:
                logger.error('Error stopping sniffer: %s', str(e))
            self._sniffer = None

        # Wait for worker thread to finish
        if self._worker_thread and self._worker_thread.is_alive():
            self._worker_thread.join(timeout=5)

        # Flush remaining buffer
        self._flush_buffer()

        logger.info(
            'Capture stopped. Total captured: %d, processed: %d',
            self._stats['packets_captured'],
            self._stats['packets_processed']
        )
        return self._stats

    def get_status(self):
        """
        Get current capture status and statistics.

        Returns:
            Dict with current capture state, counts, mode, interface, etc.
        """
        with self._lock:
            stats = dict(self._stats)
            stats['queue_size'] = self._packet_queue.qsize()
            stats['buffer_size'] = len(self._packet_buffer)
            if self._stats['start_time'] and self._running:
                start = datetime.fromisoformat(self._stats['start_time'])
                elapsed = (datetime.now() - start).total_seconds()
                stats['elapsed_seconds'] = round(elapsed, 1)
                stats['pps'] = round(
                    self._stats['packets_captured'] / max(elapsed, 1), 1
                )
            return stats

    def get_recent_packets(self, limit=50):
        """
        Get the most recently captured packets for live display.

        Args:
            limit: Maximum number of packets to return

        Returns:
            List of packet data dicts (most recent first)
        """
        with self._lock:
            packets = list(self._recent_packets)
            return packets[-limit:]

    # ============================================================
    # LIVE CAPTURE
    # ============================================================
    def _start_live_capture(self):
        """Start Scapy AsyncSniffer for real packet capture."""
        try:
            sniffer_kwargs = {
                'prn': self._packet_callback,
                'store': False,  # Don't accumulate packets in memory
                'filter': CAPTURE_FILTER if CAPTURE_FILTER else None,
            }
            if CAPTURE_INTERFACE:
                sniffer_kwargs['iface'] = CAPTURE_INTERFACE

            self._sniffer = AsyncSniffer(**sniffer_kwargs)
            self._sniffer.start()
            logger.info('Live capture started on interface: %s',
                        CAPTURE_INTERFACE or 'default')
        except Exception as e:
            logger.error('Failed to start live capture: %s', str(e))
            logger.info('Falling back to simulation mode')
            self._stats['mode'] = 'simulation'
            self._start_simulation()

    def _packet_callback(self, packet):
        """
        Scapy prn callback — minimal processing to avoid packet drops.
        Extracts essential fields and queues for batch processing.

        Args:
            packet: Scapy packet object
        """
        try:
            if not self._running:
                return

            packet_data = self._extract_packet_data(packet)
            if packet_data:
                try:
                    self._packet_queue.put_nowait(packet_data)
                    with self._lock:
                        self._stats['packets_captured'] += 1
                except queue.Full:
                    with self._lock:
                        self._stats['packets_dropped'] += 1
        except Exception:
            pass  # Never let callback exceptions crash the sniffer

    def _extract_packet_data(self, packet):
        """
        Extract relevant fields from a Scapy packet.

        Args:
            packet: Scapy packet object

        Returns:
            Dict with extracted packet fields, or None if not IP packet
        """
        if not SCAPY_AVAILABLE:
            return None

        if not packet.haslayer(IP):
            return None

        ip_layer = packet[IP]
        data = {
            'timestamp': datetime.now().isoformat(),
            'src_ip': ip_layer.src,
            'dst_ip': ip_layer.dst,
            'src_port': None,
            'dst_port': None,
            'protocol': 'OTHER',
            'packet_size': len(packet),
            'flags': '',
            'info': ''
        }

        if packet.haslayer(TCP):
            tcp_layer = packet[TCP]
            data['protocol'] = 'TCP'
            data['src_port'] = tcp_layer.sport
            data['dst_port'] = tcp_layer.dport
            data['flags'] = str(tcp_layer.flags)
            data['info'] = f'TCP {tcp_layer.sport}->{tcp_layer.dport} [{tcp_layer.flags}]'
        elif packet.haslayer(UDP):
            udp_layer = packet[UDP]
            data['protocol'] = 'UDP'
            data['src_port'] = udp_layer.sport
            data['dst_port'] = udp_layer.dport
            data['info'] = f'UDP {udp_layer.sport}->{udp_layer.dport}'
        elif packet.haslayer(ICMP):
            icmp_layer = packet[ICMP]
            data['protocol'] = 'ICMP'
            data['info'] = f'ICMP type={icmp_layer.type} code={icmp_layer.code}'

        return data

    # ============================================================
    # SIMULATION MODE
    # ============================================================
    def _start_simulation(self):
        """Start generating synthetic network traffic for demonstration."""
        self._sim_thread = threading.Thread(
            target=self._simulation_loop, daemon=True, name='PacketSimulator'
        )
        self._sim_thread.start()
        logger.info('Simulation mode started (%d packets/sec)', SIMULATION_PPS)

    def _simulation_loop(self):
        """
        Generate realistic synthetic packets at configured rate.
        Periodically injects attack patterns to trigger all detection engines:
        - Port scan: Single IP probing 25+ ports on a target
        - Brute force: Repeated connections to SSH/RDP from one IP
        - Suspicious flood: Burst of packets from a single source
        """
        # Realistic IP ranges for simulation
        internal_ips = [f'192.168.1.{i}' for i in range(1, 50)]
        external_ips = [
            '8.8.8.8', '8.8.4.4', '1.1.1.1', '208.67.222.222',
            '142.250.80.46', '151.101.1.69', '104.244.42.65',
            '13.107.42.14', '20.190.159.23', '172.217.14.206',
            '31.13.65.36', '157.240.1.35', '52.96.166.130',
            '40.126.32.80', '23.215.0.138', '104.18.32.7',
        ]
        attacker_ips = [
            '45.33.32.156', '185.220.101.34', '89.248.167.131',
            '94.102.49.190', '171.25.193.78', '198.96.155.3'
        ]
        common_ports = [80, 443, 8080, 53, 22, 3389, 21, 25, 110, 993, 587, 3306, 5432]
        protocols = ['TCP', 'TCP', 'TCP', 'TCP', 'UDP', 'UDP', 'ICMP']

        # Attack scheduling
        next_attack_time = time.time() + random.randint(15, 30)
        attack_types = ['port_scan', 'brute_force', 'suspicious_flood']

        while self._running:
            try:
                # ---- Normal Traffic ----
                for _ in range(max(1, SIMULATION_PPS)):
                    protocol = random.choice(protocols)
                    src_ip = random.choice(internal_ips)
                    dst_ip = random.choice(external_ips + internal_ips[:5])

                    packet_data = {
                        'timestamp': datetime.now().isoformat(),
                        'src_ip': src_ip,
                        'dst_ip': dst_ip,
                        'src_port': random.randint(49152, 65535) if protocol != 'ICMP' else None,
                        'dst_port': random.choice(common_ports) if protocol != 'ICMP' else None,
                        'protocol': protocol,
                        'packet_size': random.randint(40, 1500),
                        'flags': self._random_tcp_flags() if protocol == 'TCP' else '',
                        'info': ''
                    }

                    if protocol == 'TCP':
                        packet_data['info'] = (
                            f"TCP {packet_data['src_port']}->{packet_data['dst_port']} "
                            f"[{packet_data['flags']}]"
                        )
                    elif protocol == 'UDP':
                        packet_data['info'] = (
                            f"UDP {packet_data['src_port']}->{packet_data['dst_port']}"
                        )
                    elif protocol == 'ICMP':
                        packet_data['info'] = f'ICMP type={random.choice([0,8])} code=0'

                    self._enqueue_packet(packet_data)

                # ---- Attack Pattern Injection ----
                if time.time() >= next_attack_time:
                    attack = random.choice(attack_types)
                    attacker = random.choice(attacker_ips)
                    target = random.choice(internal_ips[:5])

                    if attack == 'port_scan':
                        self._inject_port_scan(attacker, target)
                    elif attack == 'brute_force':
                        self._inject_brute_force(attacker, target)
                    elif attack == 'suspicious_flood':
                        self._inject_suspicious_flood(attacker, target)

                    # Schedule next attack in 30-90 seconds
                    next_attack_time = time.time() + random.randint(30, 90)

                time.sleep(1.0)
            except Exception as e:
                logger.error('Simulation error: %s', str(e))
                time.sleep(1)

    def _inject_port_scan(self, attacker_ip, target_ip):
        """
        Simulate a port scan attack: single IP probing 25+ ports rapidly.
        Triggers PortScanDetector (threshold: 20 ports in 10s).
        """
        logger.info('SIM: Injecting port scan from %s -> %s', attacker_ip, target_ip)
        start_port = random.randint(1, 1000)
        for i in range(25):
            packet_data = {
                'timestamp': datetime.now().isoformat(),
                'src_ip': attacker_ip,
                'dst_ip': target_ip,
                'src_port': random.randint(49152, 65535),
                'dst_port': start_port + i,
                'protocol': 'TCP',
                'packet_size': random.randint(40, 64),
                'flags': 'S',  # SYN-only = classic port scan
                'info': f'TCP {start_port + i} [SYN] Port Scan'
            }
            self._enqueue_packet(packet_data)

    def _inject_brute_force(self, attacker_ip, target_ip):
        """
        Simulate a brute force attack: 15 rapid connections to SSH or RDP.
        Triggers BruteForceDetector (threshold: 10 attempts in 60s).
        """
        target_port = random.choice([22, 3389, 21, 3306])
        service = {22: 'SSH', 3389: 'RDP', 21: 'FTP', 3306: 'MySQL'}[target_port]
        logger.info('SIM: Injecting %s brute force from %s -> %s:%d',
                     service, attacker_ip, target_ip, target_port)
        for _ in range(15):
            packet_data = {
                'timestamp': datetime.now().isoformat(),
                'src_ip': attacker_ip,
                'dst_ip': target_ip,
                'src_port': random.randint(49152, 65535),
                'dst_port': target_port,
                'protocol': 'TCP',
                'packet_size': random.randint(60, 120),
                'flags': 'S',
                'info': f'TCP -> {target_port} [{service} Login Attempt]'
            }
            self._enqueue_packet(packet_data)

    def _inject_suspicious_flood(self, attacker_ip, target_ip):
        """
        Simulate suspicious traffic: burst of 40+ packets from single IP.
        Triggers SuspiciousActivityDetector (excessive packet threshold).
        """
        logger.info('SIM: Injecting traffic flood from %s -> %s', attacker_ip, target_ip)
        dst_port = random.choice([80, 443])
        for _ in range(45):
            packet_data = {
                'timestamp': datetime.now().isoformat(),
                'src_ip': attacker_ip,
                'dst_ip': target_ip,
                'src_port': random.randint(49152, 65535),
                'dst_port': dst_port,
                'protocol': 'TCP',
                'packet_size': random.randint(40, 80),
                'flags': random.choice(['S', 'SA', 'A']),
                'info': f'TCP -> {dst_port} [Flood]'
            }
            self._enqueue_packet(packet_data)

    def _enqueue_packet(self, packet_data):
        """Enqueue a single packet, updating stats."""
        try:
            self._packet_queue.put_nowait(packet_data)
            with self._lock:
                self._stats['packets_captured'] += 1
        except queue.Full:
            with self._lock:
                self._stats['packets_dropped'] += 1

    @staticmethod
    def _random_tcp_flags():
        """Generate realistic random TCP flags for simulation."""
        flag_combos = ['S', 'SA', 'A', 'PA', 'FA', 'RA', 'S', 'SA', 'PA', 'A', 'A', 'PA']
        return random.choice(flag_combos)

    # ============================================================
    # QUEUE PROCESSING
    # ============================================================
    def _process_queue(self):
        """
        Worker thread: reads packets from queue, calls detection
        callbacks, and batch-inserts into database.
        """
        logger.info('Packet processing worker started')

        while self._running or not self._packet_queue.empty():
            try:
                # Get packet with timeout to allow periodic flush
                try:
                    packet_data = self._packet_queue.get(timeout=1.0)
                except queue.Empty:
                    # Flush buffer on timeout even if batch not full
                    self._flush_buffer()
                    continue

                # Add to recent packets for live display
                with self._lock:
                    self._recent_packets.append(packet_data)
                    self._stats['packets_processed'] += 1

                # Notify all registered detection callbacks
                for callback in self._packet_callbacks:
                    try:
                        callback(packet_data)
                    except Exception as e:
                        logger.error('Packet callback error: %s', str(e))

                # Add to buffer for batch DB insert
                self._packet_buffer.append(packet_data)

                # Flush buffer if batch is full
                if len(self._packet_buffer) >= PACKET_BATCH_SIZE:
                    self._flush_buffer()
                elif time.time() - self._last_flush_time >= PACKET_BATCH_TIMEOUT:
                    self._flush_buffer()

            except Exception as e:
                logger.error('Queue processing error: %s', str(e))

        # Final flush
        self._flush_buffer()
        logger.info('Packet processing worker stopped')

    def _flush_buffer(self):
        """Batch insert buffered packets into the database."""
        if not self._packet_buffer:
            return

        try:
            db.insert_traffic_logs_batch(self._packet_buffer)
            self._packet_buffer = []
            self._last_flush_time = time.time()
        except Exception as e:
            logger.error('Failed to flush packet buffer: %s', str(e))
            # Keep buffer for retry, but limit size
            if len(self._packet_buffer) > PACKET_BATCH_SIZE * 5:
                self._packet_buffer = self._packet_buffer[-PACKET_BATCH_SIZE:]
