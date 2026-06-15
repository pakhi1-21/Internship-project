# Software Requirements Specification (SRS)
## NetSight — AI-Powered Network Traffic Monitoring and Attack Detection System

**Version:** 1.0  
**Date:** June 2026  
**Prepared for:** B.Tech Cyber Security Internship

---

## 1. Introduction

### 1.1 Purpose
This document specifies the software requirements for NetSight, a real-time network traffic monitoring and attack detection system. It serves as the definitive reference for the design, implementation, and testing of the system.

### 1.2 Scope
NetSight monitors live network traffic, captures packets, detects multiple attack types (port scanning, brute force, suspicious patterns), employs AI-based anomaly detection, and provides a web-based dashboard for security analysts.

### 1.3 Definitions & Abbreviations
| Term | Definition |
|------|-----------|
| PPS | Packets Per Second |
| SYN | TCP Synchronize flag |
| RST | TCP Reset flag |
| IDS | Intrusion Detection System |
| ML | Machine Learning |
| BPF | Berkeley Packet Filter |
| CRUD | Create, Read, Update, Delete |
| API | Application Programming Interface |

---

## 2. Overall Description

### 2.1 Product Perspective
NetSight is a standalone web-based application that runs on a local machine. It interfaces directly with the network interface card (NIC) for packet capture and provides a browser-based dashboard.

### 2.2 User Classes
| User | Description |
|------|-------------|
| Security Analyst | Primary user — monitors dashboard, reviews alerts, generates reports |
| System Administrator | Configures detection thresholds, manages system settings |
| Student/Researcher | Uses the system for learning and demonstrating cybersecurity concepts |

### 2.3 Operating Environment
- **OS:** Windows 10/11 (with Npcap), Linux (with libpcap)
- **Python:** 3.10+
- **Browser:** Chrome, Firefox, Edge (modern)
- **Network:** Access to a network interface for packet capture

### 2.4 Constraints
- SQLite limits concurrent write throughput
- Scapy is Python-based and may drop packets at very high traffic rates (>100K pps)
- AI model requires baseline training period before generating predictions

---

## 3. Functional Requirements

### FR-01: Packet Capture
| ID | Requirement |
|----|-------------|
| FR-01.1 | The system SHALL capture live network packets using Scapy |
| FR-01.2 | The system SHALL support TCP, UDP, and ICMP protocols |
| FR-01.3 | The system SHALL extract source IP, destination IP, source port, destination port, protocol, packet size, timestamp, and TCP flags |
| FR-01.4 | The system SHALL store captured packet data in SQLite database |
| FR-01.5 | The system SHALL provide a simulation mode for environments without packet capture support |
| FR-01.6 | The system SHALL provide start/stop control for packet capture |

### FR-02: Traffic Analysis
| ID | Requirement |
|----|-------------|
| FR-02.1 | The system SHALL calculate packets per second |
| FR-02.2 | The system SHALL track active connections |
| FR-02.3 | The system SHALL identify top 10 source IPs by packet count |
| FR-02.4 | The system SHALL identify top 10 destination ports |
| FR-02.5 | The system SHALL compute protocol distribution percentages |
| FR-02.6 | The system SHALL calculate traffic volume in bytes per second |

### FR-03: Port Scan Detection
| ID | Requirement |
|----|-------------|
| FR-03.1 | The system SHALL detect when a source IP accesses more than 20 unique ports within 10 seconds |
| FR-03.2 | The system SHALL classify scans as SYN Scan, Fast Scan, or Sequential Scan |
| FR-03.3 | The system SHALL generate an alert with attacker IP, port count, and scan type |

### FR-04: Brute Force Detection
| ID | Requirement |
|----|-------------|
| FR-04.1 | The system SHALL monitor connection attempts to known service ports (SSH, RDP, FTP, etc.) |
| FR-04.2 | The system SHALL detect >10 connection attempts to the same service within 60 seconds |
| FR-04.3 | The system SHALL generate an alert with source IP, attempt count, and target service |

### FR-05: Suspicious Activity Detection
| ID | Requirement |
|----|-------------|
| FR-05.1 | The system SHALL detect traffic spikes using statistical analysis (mean + 3σ) |
| FR-05.2 | The system SHALL flag IPs with packet rates exceeding 100 pps |
| FR-05.3 | The system SHALL detect IPs connecting to more than 50 unique destinations |
| FR-05.4 | The system SHALL generate a weighted threat score (0-100) |

### FR-06: AI Anomaly Detection
| ID | Requirement |
|----|-------------|
| FR-06.1 | The system SHALL use Isolation Forest for anomaly detection |
| FR-06.2 | The system SHALL train on 5 features: packet rate, connection rate, unique IP count, unique port count, average packet size |
| FR-06.3 | The system SHALL classify traffic as Normal (0-30), Suspicious (31-70), or Malicious (71-100) |
| FR-06.4 | The system SHALL auto-train after collecting sufficient baseline samples |
| FR-06.5 | The system SHALL persist the trained model to disk |

### FR-07: Alert Management
| ID | Requirement |
|----|-------------|
| FR-07.1 | The system SHALL support severity levels: LOW, MEDIUM, HIGH, CRITICAL |
| FR-07.2 | The system SHALL deduplicate alerts within a configurable time window |
| FR-07.3 | The system SHALL store all alerts in the database |
| FR-07.4 | The system SHALL allow alerts to be marked as resolved |

### FR-08: Web Dashboard
| ID | Requirement |
|----|-------------|
| FR-08.1 | The system SHALL display a dashboard with total packets, active connections, alerts, and threat score |
| FR-08.2 | The system SHALL provide a live traffic viewer with filtering |
| FR-08.3 | The system SHALL display alerts with tabbed filtering by type |
| FR-08.4 | The system SHALL show interactive charts (traffic trends, protocol distribution, attack history) |
| FR-08.5 | The system SHALL auto-refresh dashboard data every 3 seconds |

### FR-09: Report Generation
| ID | Requirement |
|----|-------------|
| FR-09.1 | The system SHALL generate reports covering traffic summary, alerts, suspicious IPs, AI findings |
| FR-09.2 | The system SHALL export reports in PDF and CSV formats |
| FR-09.3 | The system SHALL provide recommendations based on findings |

### FR-10: Logging
| ID | Requirement |
|----|-------------|
| FR-10.1 | The system SHALL log system events to system.log |
| FR-10.2 | The system SHALL log security alerts to alerts.log |
| FR-10.3 | The system SHALL use rotating file handlers to manage log file sizes |

---

## 4. Non-Functional Requirements

| ID | Category | Requirement |
|----|----------|-------------|
| NFR-01 | Performance | The system SHALL process at least 15 packets per second in simulation mode |
| NFR-02 | Performance | Dashboard SHALL refresh within 3 seconds |
| NFR-03 | Usability | The web interface SHALL be responsive on desktop and tablet |
| NFR-04 | Security | All database queries SHALL use parameterized statements |
| NFR-05 | Security | Report filenames SHALL be sanitized before serving |
| NFR-06 | Reliability | The system SHALL auto-recover from packet capture failures |
| NFR-07 | Maintainability | Configuration SHALL be centralized in config.py |
| NFR-08 | Portability | The system SHALL support Windows and Linux |

---

## 5. Database Schema

### 5.1 traffic_logs
| Column | Type | Description |
|--------|------|-------------|
| id | INTEGER PK | Auto-increment ID |
| timestamp | TEXT | ISO 8601 timestamp |
| src_ip | TEXT | Source IP address |
| dst_ip | TEXT | Destination IP address |
| src_port | INTEGER | Source port (nullable) |
| dst_port | INTEGER | Destination port (nullable) |
| protocol | TEXT | Protocol (TCP/UDP/ICMP) |
| packet_size | INTEGER | Packet size in bytes |
| flags | TEXT | TCP flags string |
| info | TEXT | Additional packet info |

### 5.2 alerts
| Column | Type | Description |
|--------|------|-------------|
| id | INTEGER PK | Auto-increment ID |
| timestamp | TEXT | ISO 8601 timestamp |
| alert_type | TEXT | Alert type enum |
| severity | TEXT | Severity level enum |
| source_ip | TEXT | Source IP |
| destination_ip | TEXT | Destination IP |
| description | TEXT | Alert description |
| details | TEXT | Additional details |
| resolved | INTEGER | 0=active, 1=resolved |
| resolved_at | TEXT | Resolution timestamp |

### 5.3 anomalies
| Column | Type | Description |
|--------|------|-------------|
| id | INTEGER PK | Auto-increment ID |
| timestamp | TEXT | ISO 8601 timestamp |
| threat_score | REAL | Score 0-100 |
| classification | TEXT | Normal/Suspicious/Malicious |
| features_json | TEXT | JSON feature vector |
| details | TEXT | Detection details |

### 5.4 settings
| Column | Type | Description |
|--------|------|-------------|
| id | INTEGER PK | Auto-increment ID |
| key | TEXT UNIQUE | Setting key |
| value | TEXT | Setting value |
| updated_at | TEXT | Last update timestamp |

### 5.5 traffic_stats
| Column | Type | Description |
|--------|------|-------------|
| id | INTEGER PK | Auto-increment ID |
| timestamp | TEXT | ISO 8601 timestamp |
| packets_per_second | REAL | PPS rate |
| active_connections | INTEGER | Connection count |
| total_bytes | INTEGER | Total bytes |
| protocol_distribution | TEXT | JSON distribution |
| top_source_ips | TEXT | JSON top IPs |
| top_dest_ports | TEXT | JSON top ports |

---

## 6. Glossary

| Term | Definition |
|------|-----------|
| Isolation Forest | Unsupervised ML algorithm that isolates anomalies by random partitioning |
| Port Scan | Technique to discover open ports on a target by sending probe packets |
| Brute Force | Attack method that tries many passwords or connection attempts |
| Threat Score | Numerical value (0-100) indicating the severity of detected anomalies |
| AsyncSniffer | Scapy's asynchronous packet capture class that runs in a background thread |
| WAL Mode | SQLite Write-Ahead Logging for improved concurrent access |
