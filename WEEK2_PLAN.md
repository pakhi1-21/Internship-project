# WEEK 2: Packet Capture & Detection Engines (Part 1)

## 🎯 Week 2 Goal
**3 detectors generating alerts, 100+ alerts in DB**

**Prerequisites:** Week 1 complete (database, logging, alerts working)

---

## 📅 Daily Breakdown

### **Day 1: Packet Sniffer Implementation**

**Objectives:**
- [ ] Implement `backend/packet_sniffer.py` with Scapy AsyncSniffer
  ```python
  class PacketSniffer:
      def start_capture()      # Start packet capture thread
      def stop_capture()       # Stop sniffer gracefully
      def get_status()         # Return capture status
      def packet_callback()    # Process each packet
      def store_packets()      # Batch insert to database
  ```

- [ ] Capture these packet types:
  - TCP packets (with SYN, ACK, RST flags)
  - UDP packets
  - ICMP packets

- [ ] Extract these fields:
  - source_ip, destination_ip
  - source_port, destination_port
  - protocol (TCP/UDP/ICMP)
  - packet_size, timestamp
  - TCP flags (SYN, ACK, RST, etc.)

- [ ] Store packets in database every 5 seconds (batch insert)

- [ ] Implement start/stop/status controls

**Deliverable:** Live packet capture working, 100+ packets/sec stored in DB

**Success Criteria:**
- [ ] `PacketSniffer` class created and instantiated
- [ ] `start_capture()` method works
- [ ] Packets appear in database `packets` table
- [ ] Can handle 1000+ pps without dropping
- [ ] `stop_capture()` stops cleanly
- [ ] Status returns accurate info

---

### **Day 2: Traffic Analyzer Module**

**Objectives:**
- [ ] Implement `backend/traffic_analyzer.py`
  ```python
  class TrafficAnalyzer:
      def get_stats()          # Calculate all metrics
      def calculate_pps()      # Packets per second
      def get_connections()    # Active connection count
      def get_protocol_dist()  # Protocol distribution %
      def get_top_ips()        # Top 10 source IPs
      def get_top_ports()      # Top 10 dest ports
      def calculate_bandwidth()# Bytes/sec
      def get_avg_packet_size()# Average size
  ```

- [ ] Analyze last 60 seconds of traffic
- [ ] Return statistics every 10 seconds

**Deliverable:** Real-time traffic stats available via function calls

**Success Criteria:**
- [ ] `TrafficAnalyzer` class created
- [ ] `get_stats()` returns dict with all metrics
- [ ] Stats calculated correctly from database packets
- [ ] PPS calculation accurate
- [ ] Top IPs/ports ranked correctly
- [ ] Can be called every 10 seconds

---

### **Day 3: Port Scan Detection**

**Objectives:**
- [ ] Implement `backend/port_scan_detector.py`
  ```python
  class PortScanDetector:
      def check_scans()        # Main detection logic
      def detect_syn_scan()    # >20 unique ports in 10 sec
      def detect_fast_scan()   # >50 ports in 5 sec
      def detect_sequential()  # Sequential ports 1,2,3...
      def generate_alert()     # Create alert record
  ```

- [ ] Detection Rules:
  - **SYN Scan:** Source IP connects to >20 unique ports in 10 seconds → HIGH severity
  - **Fast Scan:** Source IP connects to >50 unique ports in 5 seconds → CRITICAL severity
  - **Sequential Scan:** Ports are 1,2,3... (pattern detection) → MEDIUM severity

- [ ] Generate alerts with:
  - Attacker IP, port count, scan type
  - Timestamp, severity level
  - Affected ports list

**Deliverable:** Port scan detection working, alerts generated in DB

**Success Criteria:**
- [ ] Detector identifies SYN scans correctly
- [ ] Detector identifies fast scans correctly
- [ ] Sequential scan pattern detection works
- [ ] Alerts created with correct severity
- [ ] Attacker IP and port info stored
- [ ] Can run continuously without crashing

---

### **Day 4: Brute Force Detection**

**Objectives:**
- [ ] Implement `backend/bruteforce_detector.py`
  ```python
  class BruteForceDetector:
      def check_brute_force()  # Main detection logic
      def monitor_services()   # Track login attempts
      def count_attempts()     # Attempts per source/port
      def generate_alert()     # Create alert record
  ```

- [ ] Monitor these service ports:
  - 22 (SSH), 3389 (RDP), 21 (FTP)
  - 80 (HTTP), 443 (HTTPS)
  - 5432 (PostgreSQL), 3306 (MySQL)
  - 1433 (MSSQL), 27017 (MongoDB)
  - 25 (SMTP), 110 (POP3), 143 (IMAP)

- [ ] Detection Rule:
  - **>10 connection attempts** to same service port from same source IP **within 60 seconds** = Brute Force

- [ ] Alert Details:
  - Source IP, target port/service
  - Number of attempts, attempt IPs
  - Severity: HIGH if >10, CRITICAL if >30

**Deliverable:** Brute force alerts generated, confidence scoring works

**Success Criteria:**
- [ ] Detector tracks connection attempts correctly
- [ ] Generates alerts when threshold >10 exceeded
- [ ] Service identification working (port → service name)
- [ ] Severity levels assigned correctly
- [ ] Attempt count accurate
- [ ] Time window (60 sec) enforced

---

### **Day 5: Integration Testing**

**Objectives:**
- [ ] Run `test_system.py` for simulated attacks
  ```powershell
  python test_system.py
  ```

- [ ] Verify port scan detection triggers:
  - Simulate scanning 25 ports → Should detect SYN scan
  - Check alert in database

- [ ] Verify brute force detection triggers:
  - Simulate 15 SSH attempts → Should detect brute force
  - Check alert in database

- [ ] Test alert storage and retrieval:
  - Query `alerts` table
  - Verify severity, timestamps, IPs

- [ ] Check logs for any errors

**Deliverable:** Both detectors working correctly in integration test

**Success Criteria:**
- [ ] `test_system.py` runs without errors
- [ ] Port scan alert generated and stored
- [ ] Brute force alert generated and stored
- [ ] Alerts visible in database
- [ ] No crashes or hangs
- [ ] Logs show successful detections
- [ ] System ready for Week 3

---

## 📋 Checklist - Week 2 Complete When:

```
Day 1 ✅ Packet Sniffer
- [ ] PacketSniffer class implemented
- [ ] Capture starts/stops cleanly
- [ ] 100+ packets/sec stored in DB
- [ ] All fields (IP, port, protocol) captured
- [ ] Status endpoint working

Day 2 ✅ Traffic Analyzer
- [ ] TrafficAnalyzer class implemented
- [ ] PPS calculated correctly
- [ ] Top IPs/ports ranked properly
- [ ] Protocol distribution working
- [ ] Bandwidth calculation accurate

Day 3 ✅ Port Scan Detector
- [ ] SYN scan detection working
- [ ] Fast scan detection working
- [ ] Sequential scan pattern detection working
- [ ] Alerts generated with correct severity
- [ ] Can detect simulated scans

Day 4 ✅ Brute Force Detector
- [ ] Service port monitoring working
- [ ] Attempt counting accurate
- [ ] >10 attempts triggers alert
- [ ] Service identification (port → name) working
- [ ] Can detect simulated brute force

Day 5 ✅ Integration Test
- [ ] test_system.py runs successfully
- [ ] Port scan alert generated and stored
- [ ] Brute force alert generated and stored
- [ ] No errors in logs
- [ ] System ready for Week 3
```

---

## 🔍 Testing Guide

### Test Port Scan Detection:
```python
# Simulate scanning ports 1000-1020 from same IP
# Should trigger SYN scan alert
```

### Test Brute Force Detection:
```python
# Simulate 15 SSH (port 22) connections from same IP in 60 sec
# Should trigger brute force alert
```

### Verify in Database:
```sql
SELECT * FROM alerts ORDER BY timestamp DESC LIMIT 10;
SELECT COUNT(*) FROM alerts WHERE alert_type='port_scan';
SELECT COUNT(*) FROM alerts WHERE alert_type='brute_force';
```

---

## 🚀 Next Steps

When Week 2 is complete, move to **Week 3** to implement:
- Suspicious activity detector
- AI anomaly detection (Isolation Forest)
- Flask API endpoints
- Dashboard integration

**Total Time:** ~40 hours (5 days × 8 hours)

