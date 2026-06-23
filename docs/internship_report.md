# Internship Report Content
## B.Tech Cyber Security Internship

### NetSight: AI-Powered Network Traffic Monitoring and Attack Detection System

---

## Abstract

This internship project presents **NetSight**, a comprehensive network traffic monitoring and attack detection system developed using Python, Flask, Scapy, and machine learning. The system captures live network packets, performs real-time traffic analysis, detects multiple attack types including port scanning and brute force attempts, and employs AI-based anomaly detection using the Isolation Forest algorithm. The solution features a modern web-based dashboard providing real-time visibility into network security posture, automated alert management, and comprehensive reporting capabilities. This project demonstrates the practical application of cybersecurity principles, network protocol analysis, and machine learning in building an effective intrusion detection system.

---

## 1. Introduction

### 1.1 Background
Network security remains one of the most critical challenges in the digital age. With increasing sophistication of cyber attacks, traditional signature-based detection systems are insufficient. Modern security tools must combine rule-based detection with machine learning to identify novel threats.

### 1.2 Problem Statement
*"Network Traffic Monitoring and Attack Detection – Develop a tool for monitoring network packets and detecting attacks such as port scanning, brute force attempts, and suspicious traffic patterns."*

### 1.3 Objectives
1. Develop a real-time packet capture and analysis engine
2. Implement detection algorithms for port scanning and brute force attacks
3. Build an AI-based anomaly detection system using Isolation Forest
4. Create a web-based dashboard for network security monitoring
5. Generate comprehensive security reports

### 1.4 Scope
The project covers packet capture, traffic analysis, attack detection (port scan, brute force, suspicious activity), AI anomaly detection, alert management, web dashboard, and report generation.

---

## 2. Literature Review

### 2.1 Intrusion Detection Systems (IDS)
Intrusion Detection Systems are classified into two categories:
- **Network-based IDS (NIDS)** — Monitors network traffic for suspicious patterns
- **Host-based IDS (HIDS)** — Monitors individual host activity

NetSight implements a NIDS approach, analyzing network packets in real-time.

### 2.2 Port Scan Detection
Port scanning is a reconnaissance technique where an attacker probes target ports to discover running services. Common types include:
- **SYN Scan** — Sends TCP SYN packets without completing the handshake
- **Connect Scan** — Completes the TCP three-way handshake
- **Sequential Scan** — Scans ports in numerical order

### 2.3 Brute Force Detection
Brute force attacks involve repeated authentication attempts against services like SSH, RDP, and FTP. Detection relies on monitoring connection frequency to specific service ports.

### 2.4 Machine Learning in Cybersecurity
The Isolation Forest algorithm is particularly suited for network anomaly detection because:
- It is unsupervised (no labeled data required)
- It works by isolating anomalies rather than profiling normal behavior
- It handles high-dimensional data efficiently
- It provides anomaly scores for probabilistic assessment

---

## 3. Methodology

### 3.1 Development Approach
The project follows a modular architecture with clear separation of concerns:
1. **Capture Layer** — Packet acquisition using Scapy
2. **Analysis Layer** — Traffic statistics and feature extraction
3. **Detection Layer** — Rule-based and ML-based threat detection
4. **Presentation Layer** — Web dashboard and REST API

### 3.2 Tools and Technologies
| Component | Technology | Purpose |
|-----------|-----------|---------|
| Backend | Python 3.10+, Flask | Application logic, API server |
| Packet Capture | Scapy | Network packet sniffing |
| Database | SQLite | Persistent data storage |
| Machine Learning | scikit-learn | Isolation Forest anomaly detection |
| Frontend | HTML/CSS/JS, Bootstrap 5 | Web dashboard |
| Visualization | Chart.js | Interactive charts |
| Reporting | ReportLab | PDF report generation |

### 3.3 Detection Algorithms

#### Port Scan Detection
- Track unique destination ports per source IP within a 10-second window
- Alert when count exceeds 20 ports
- Classify as SYN Scan, Fast Scan, or Sequential Scan

#### Brute Force Detection
- Monitor TCP SYN packets to known service ports
- Track connection count per (source IP, destination port) pair
- Alert when count exceeds 10 within 60 seconds

#### AI Anomaly Detection
- **Features:** packet_rate, connection_rate, unique_ip_count, unique_port_count, avg_packet_size
- **Model:** Isolation Forest (contamination=0.1, n_estimators=100)
- **Classification:** Normal (0-30), Suspicious (31-70), Malicious (71-100)

---

## 4. Implementation

### 4.1 System Architecture
The system consists of 12 modules organized in a pipeline architecture:

1. **Packet Sniffer** — Captures packets using AsyncSniffer with queue-based processing
2. **Traffic Analyzer** — Computes sliding window statistics
3. **Port Scan Detector** — Monitors port access patterns
4. **Brute Force Detector** — Tracks service connection attempts
5. **Suspicious Activity Detector** — Statistical anomaly detection
6. **AI Detector** — Isolation Forest machine learning model
7. **Alert Manager** — Centralized alert handling with deduplication
8. **Database** — SQLite with 5 tables and indexed queries
9. **Web Dashboard** — 5-page responsive interface
10. **Report Generator** — PDF and CSV security reports
11. **Logging System** — Rotating file-based logging
12. **Email Alerts** — SMTP notifications for critical alerts

### 4.2 Key Implementation Details

#### Packet Processing Pipeline
```
AsyncSniffer → Queue → Worker Thread → [Analyzer, Detectors] → Database
```
The queue-based architecture prevents packet drops by separating capture from processing.

#### AI Model Training
The system auto-trains the Isolation Forest model after collecting 100+ baseline samples. The model uses StandardScaler for feature normalization and persists to disk using joblib.

#### Real-time Dashboard
The frontend uses JavaScript fetch API to poll backend endpoints every 3 seconds, updating Chart.js visualizations and data tables without page reloads.

---

## 5. Results

### 5.1 Detection Effectiveness
Testing with the built-in simulation system confirmed:
- **Port Scan Detection** — Successfully detects SYN, fast, and sequential scans
- **Brute Force Detection** — Correctly identifies repeated connection attempts to service ports
- **Traffic Spike Detection** — Statistically identifies abnormal traffic rates
- **AI Anomaly Detection** — Isolation Forest correctly classifies normal vs. anomalous traffic

### 5.2 Performance
- Simulation mode processes 15+ packets per second
- Dashboard refresh latency: <500ms
- AI model training time: <2 seconds for 150 samples
- Database queries: <50ms for typical dashboard loads

### 5.3 Dashboard Features
- Real-time stat cards with animated counters
- Interactive traffic, protocol, and attack charts
- Tabbed alert management with severity filtering
- PDF/CSV report generation with recommendations

---

## 6. Conclusion

NetSight successfully demonstrates the development of a complete network traffic monitoring and attack detection system. The project integrates packet capture, multiple detection algorithms, machine learning-based anomaly detection, and a modern web dashboard into a cohesive security tool.

### Key Achievements
1. Implemented real-time packet capture with simulation fallback
2. Built 3 rule-based detection engines for different attack types
3. Integrated Isolation Forest for unsupervised anomaly detection
4. Created a professional 5-page cybersecurity dashboard
5. Automated report generation with actionable recommendations

### Limitations
- SQLite limits concurrent write throughput for high-traffic networks
- Scapy-based capture may miss packets at very high rates (>100K pps)
- AI model effectiveness depends on quality of baseline training data

---

## 7. Future Work

1. **Deep Learning** — Replace Isolation Forest with LSTM/Autoencoder for temporal pattern detection
2. **Distributed Monitoring** — Support multiple network sensors with centralized dashboard
3. **Threat Intelligence** — Integrate IP reputation databases and STIX/TAXII feeds
4. **Advanced Protocol Analysis** — HTTP/DNS inspection for application-layer attacks
5. **Real-time Blocking** — Integrate with firewall APIs for automated response
6. **Cloud Deployment** — Containerize with Docker and deploy to cloud infrastructure

---

## 8. References

1. Scapy Project — https://scapy.net/
2. scikit-learn IsolationForest — https://scikit-learn.org/stable/modules/generated/sklearn.ensemble.IsolationForest.html
3. Flask Documentation — https://flask.palletsprojects.com/
4. Chart.js — https://www.chartjs.org/
5. Bootstrap 5 — https://getbootstrap.com/
6. Liu, F.T., Ting, K.M., & Zhou, Z.H. (2008). Isolation Forest. ICDM.
7. NIST SP 800-94: Guide to Intrusion Detection and Prevention Systems
8. Stallings, W. (2020). Network Security Essentials. Pearson.
