# NetSight

## Intelligent Network Packet Analysis and Cybersecurity Threat Identification Platform

<p align="center">
  <strong>🛡️ Live traffic surveillance • 🤖 Machine learning-powered threat detection • 📊 Rich visualization interface</strong>
</p>

---

## 📋 Quick Navigation

- [About](#about)
- [Capabilities](#capabilities)
- [Technology Stack](#technology-stack)
- [Directory Layout](#directory-layout)
- [Setup Instructions](#setup-instructions)
- [Getting Started](#getting-started)
- [REST Endpoints](#rest-endpoints)
- [Validation & Debugging](#validation--debugging)
- [System Design](#system-design)
- [Demo Images](#demo-images)
- [Copyright & Usage](#copyright--usage)

---

## 🔍 About

**NetSight** serves as a powerful network observation and threat identification platform tailored for security researchers and cybersecurity trainees. The platform captures incoming and outgoing network packets in real-time, examines communication flows, identifies multiple categories of intrusions and threats, and leverages machine learning models to flag unusual behavior and potential compromises.

The platform directly addresses this challenge:

> *"Network Packet Surveillance and Intrusion Recognition – Create a system for analyzing network communications and recognizing intrusions including network reconnaissance, credential attack attempts, and atypical data transmission."*

---

## ✨ Capabilities

### Packet & Traffic Observation
- **Real-Time Packet Inspection** — Immediate TCP, UDP, and ICMP packet interception using Scapy library
- **Connection Statistics** — Data transmission speed, ongoing sessions, network protocol breakdown
- **Fallback Traffic Generation** — Creates synthetic network flows when Npcap driver is not available

### Intrusion & Threat Recognition
- **Reconnaissance Detection** — Identifies SYN-based port enumeration, rapid scanning, methodical network probes
- **Credential Attack Identification** — Spots repetitive unauthorized access tries targeting SSH, RDP, FTP, and many other services
- **Unusual Pattern Recognition** — Detects bandwidth surges, irregular packet transmission, atypical connection behaviors
- **Supervised Learning Threat Scoring** — Isolation Forest algorithm for self-managed anomaly categorization

### Interactive Environment & Documentation
- **Browser-Based Monitoring Console** — 5-section responsive interface with dark cybersecurity aesthetic
- **Dynamic Visualizations** — Live protocol analysis, incident timeline, detection event history (Chart.js)
- **Incident Tracking** — Priority-ranked incident logs with filtering capability and closure status
- **Security Documentation** — PDF and CSV compliance reports including remediation suggestions
- **Automated Notifications** — Optional message alerts for significant security events

### Intelligence Engine
- **Unsupervised Pattern Learning** — Isolation Forest for discovering novel threats
- **Feature Extraction** — Five behavioral indicators extracted from network streams
- **Continuous Adjustment** — Algorithm calibrates against observed baseline patterns
- **Risk Classification** — Numerical scoring from 0-100 with categories for Safe/Questionable/Dangerous

---

## 🛠️ Technology Stack

| Layer | Tools & Frameworks |
|-------|------------------|
| Application Server | Python 3.10 or newer, Flask microframework |
| Network Capture | Scapy (AsyncSniffer) |
| Persistent Storage | SQLite3 database |
| Predictive Analytics | scikit-learn library (Isolation Forest) |
| Web Interface | HTML5, CSS3, JavaScript (Modern ES6) |
| Visual Design | Bootstrap 5.3 responsive framework |
| Data Visualization | Chart.js 4.x charting library |
| File Generation | ReportLab for PDF creation |
| Visual Elements | Font Awesome 6 icon set |
| Typography | Inter and JetBrains Mono font families

---

## 📁 Directory Layout

```
NetSight/
├── app.py                          # Primary application server entry point
├── config.py                       # System-wide settings and parameters
├── requirements.txt                # Required Python packages
├── setup.bat                       # Automated installation batch script
├── test_system.py                  # Verification and emulation utilities
├── README.md                       # Documentation
│
├── backend/                        # Application logic modules
│   ├── __init__.py
│   ├── packet_sniffer.py           # Live packet acquisition mechanism
│   ├── traffic_analyzer.py         # Network flow measurements
│   ├── port_scan_detector.py       # Network reconnaissance identifier
│   ├── bruteforce_detector.py      # Authentication attack recognizer
│   ├── suspicious_activity_detector.py  # Anomalous behavior locator
│   ├── ai_detector.py             # Machine learning classifier (Isolation Forest)
│   ├── alert_manager.py           # Security incident management
│   ├── database.py                # Data persistence layer
│   ├── report_generator.py        # Documentation exporters
│   ├── email_alerts.py            # Message alert system
│   └── logger.py                  # Event recording mechanism
│
├── templates/                      # Server-side page templates
│   ├── base.html                   # Master template (navigation + structure)
│   ├── dashboard.html              # Primary monitoring interface
│   ├── traffic.html                # Packet stream display
│   ├── alerts.html                 # Incident viewer
│   ├── analytics.html              # Statistical visualizations
│   └── reports.html                # Report creation interface
│
├── static/                         # Client-side resources
│   ├── css/style.css               # Interface styling with security theme
│   └── js/
│       ├── dashboard.js            # Dashboard interactive behavior
│       ├── traffic.js              # Packet display scripting
│       ├── alerts.js               # Alert management client code
│       ├── analytics.js            # Chart rendering scripts
│       └── reports.js              # Report page interactivity
│
├── database/                       # Auto-created SQLite storage
│   └── netsight.db
│
├── logs/                           # System event records
│   ├── system.log
│   └── alerts.log
│
├── reports/                        # Generated security documentation (PDF/CSV)
├── models/                         # Serialized machine learning models
│
└── docs/                           # Technical documentation
    ├── SRS.md                      # Software Requirements Specification
    ├── architecture_diagram.md
    ├── data_flow_diagram.md
    ├── use_case_diagram.md
    └── internship_report.md
```

---

## 🚀 Setup Instructions

### System Requirements
- Python 3.10 or above
- pip (Package installer tool)
- **Recommended:** [Npcap](https://npcap.com/) for Windows packet interception capability

### Automated Installation (Windows)

```batch
# Download or retrieve the repository
cd NetSight

# Execute automated setup
setup.bat
```

### Hands-On Installation

```bash
# Create isolated Python environment
python -m venv venv

# Engage environment (Windows)
venv\Scripts\activate

# Engage environment (macOS/Linux)
source venv/bin/activate

# Obtain all packages
pip install -r requirements.txt

# Prepare database
python -c "from backend.database import init_db; init_db()"
```

---

## 💻 Getting Started

### Launching the Platform

```bash
# Engage isolated environment
venv\Scripts\activate

# Initialize NetSight
python app.py
```

The monitoring interface becomes accessible at: **http://localhost:5000**

### Accessing Different Sections

| Section | Uniform Resource Locator | Content |
|---------|--------------------------|---------|
| Summary Screen | `/` | Key metrics, visualizations, threat assessment status |
| Network Streams | `/traffic` | Ongoing packet surveillance |
| Security Events | `/alerts` | Detected incidents with sorting |
| Statistical Analysis | `/analytics` | Trend graphs and network examination |
| Documentation Export | `/reports` | Generate and retrieve security documents |

### Operating Methods

- **Captured Flows** — Records genuine network traffic (Npcap prerequisite)
- **Generated Flows** — Produces synthetic connections for demonstration (automatic fallback)

---

## 📡 REST Endpoints

### Dashboard Statistics
| Route | Verb | Function |
|-------|------|----------|
| `/api/dashboard` | GET | Consolidated system metrics |

### Network Flow Data
| Route | Verb | Parameters | Function |
|-------|------|-----------|----------|
| `/api/traffic` | GET | `limit`, `offset`, `protocol`, `src_ip` | Historical packet records |
| `/api/traffic/stats` | GET | — | Contemporary connection data |

### Incident Management
| Route | Verb | Parameters | Function |
|-------|------|-----------|----------|
| `/api/alerts` | GET | `limit`, `type`, `severity` | Indexed incident collection |
| `/api/alerts/<id>/resolve` | POST | — | Mark incident as addressed |

### Behavioral Detection
| Route | Verb | Function |
|-------|------|----------|
| `/api/anomalies` | GET | Machine learning evaluation output |

### Security Reporting
| Route | Verb | Function |
|-------|------|----------|
| `/api/reports/generate` | POST | Create compliance document |
| `/api/reports` | GET | Index available documents |
| `/api/reports/<filename>` | GET | Retrieve document file |

### Packet Interception Control
| Route | Verb | Function |
|-------|------|----------|
| `/api/capture/start` | POST | Commence traffic recording |
| `/api/capture/stop` | POST | Discontinue traffic recording |
| `/api/capture/status` | GET | Current recording condition |

---

## 🧪 Validation & Debugging

### Automated Validation Suite

```bash
# Execute comprehensive tests
python test_system.py

# Execute individual scenario
python test_system.py port_scan
python test_system.py brute_force
python test_system.py spike
python test_system.py ai
```

### Interactive Scenario Testing

#### Network Reconnaissance Identification (using Nmap)
```bash
nmap -sS -p 1-100 <target_ip>
```

#### Credential Attack Identification
```bash
# Emulate SSH credential assault (hydra or custom implementation)
# Framework detects >10 tries to port 22 within 60 seconds
```

#### Bandwidth Surge Recognition
```bash
# Use traffic generator like hping3
hping3 -S --flood <target_ip>
```

---

## 🏗️ System Design

The framework employs a segmented stream-based architecture:

```
Network Interface Card
       ↓
┌─────────────────┐
│  Packet Reader  │ (Scapy AsyncSniffer / Emulation)
└────────┬────────┘
         ↓
   ┌─────────────┐
   │  Buffer     │ (Concurrent-safe packet reservoir)
   └──────┬──────┘
          ↓
   ┌──────────────────────────────────────┐
   │      Packet Handler             │
   │  (Accumulated storage + branch out)      │
   └──┬────────┬────────┬────────┬───────┘
      ↓        ↓        ↓        ↓
   Bandwidth Network  Credential Abnormal
   Analyzer Probe     Assault   Activity
             Locator  Finder    Finder
      ↓        ↓        ↓        ↓
   ┌──────────────────────────────────────┐
   │          Incident Handler            │
   │  (Eliminate dupes + Store + Notify)  │
   └──────────────┬──────────────────────┘
                  ↓
   ┌──────────────────────────────────────┐
   │          Threat Classifier           │
   │  (Isolation Forest → Risk Index)     │
   └──────────────┬──────────────────────┘
                  ↓
   ┌──────────────────────────────────────┐
   │       Browser-Based System           │
   │  (HTML/CSS/JS + Web service points)  │
   └──────────────────────────────────────┘
```

---

## 🔒 Privacy & Integrity

- **Protected Database Operations** — Escaped variable interpolation safeguards against code injection
- **Request Validation** — All user-submitted data checked for correctness
- **Safe File Handling** — Document downloads sanitize filenames to prevent exploits
- **Secured Sessions** — Encrypted browser cookies with swappable master key
- **Concurrent Consistency** — Database employs Write-Ahead Logging for synchronized multi-user access

---

## 📄 Copyright & Usage

This initiative is created for educational purposes as component of a Bachelor's Degree Cyber Security Apprenticeship.

---

<p align="center">
  <strong>NetSight</strong> — Safeguarding infrastructure with smart analysis<br>
  Engineered with ❤️ for information security
</p>
