# Data Flow Diagram
## NetSight Data Flow

### Level 0 — Context Diagram

```mermaid
graph LR
    NET["Network Traffic"] --> NV["NetSight System"]
    NV --> ANALYST["Security Analyst"]
    NV --> EMAIL["Email Recipient"]
    ANALYST --> NV

    style NET fill:#1a1a2e,stroke:#00d4ff,color:#e8ecf1
    style NV fill:#0d1321,stroke:#00d4ff,color:#e8ecf1
    style ANALYST fill:#1a1a2e,stroke:#10b981,color:#e8ecf1
    style EMAIL fill:#1a1a2e,stroke:#ec4899,color:#e8ecf1
```

### Level 1 — Detailed Data Flow

```mermaid
graph TB
    subgraph "External Entities"
        NET["Network Interface"]
        USER["Security Analyst"]
        MAIL["Email System"]
    end

    subgraph "Processes"
        P1["1.0<br/>Capture Packets"]
        P2["2.0<br/>Analyze Traffic"]
        P3["3.0<br/>Detect Attacks"]
        P4["4.0<br/>AI Analysis"]
        P5["5.0<br/>Manage Alerts"]
        P6["6.0<br/>Generate Reports"]
        P7["7.0<br/>Serve Dashboard"]
    end

    subgraph "Data Stores"
        D1["D1: traffic_logs"]
        D2["D2: alerts"]
        D3["D3: anomalies"]
        D4["D4: traffic_stats"]
        D5["D5: AI Model"]
        D6["D6: Log Files"]
        D7["D7: Report Files"]
    end

    NET -->|"Raw Packets"| P1
    P1 -->|"Parsed Packet Data"| D1
    P1 -->|"Packet Stream"| P2
    P1 -->|"Packet Stream"| P3

    P2 -->|"Statistics"| D4
    P2 -->|"Features"| P4

    P3 -->|"Detection Events"| P5
    P4 -->|"Anomaly Results"| D3
    P4 -->|"Anomaly Alerts"| P5

    P5 -->|"Alert Records"| D2
    P5 -->|"Alert Logs"| D6
    P5 -->|"Critical Alerts"| MAIL

    P4 -->|"Trained Model"| D5
    D5 -->|"Model Parameters"| P4

    D1 -->|"Traffic Data"| P6
    D2 -->|"Alert Data"| P6
    D3 -->|"Anomaly Data"| P6
    P6 -->|"PDF/CSV"| D7

    D1 -->|"Traffic Data"| P7
    D2 -->|"Alert Data"| P7
    D3 -->|"Anomaly Data"| P7
    D4 -->|"Stats Data"| P7
    D7 -->|"Report Files"| P7

    P7 -->|"Dashboard/API"| USER
    USER -->|"Commands"| P7
    USER -->|"Report Request"| P6

    MAIL -->|"Notifications"| USER

    style NET fill:#1a1a2e,stroke:#00d4ff,color:#e8ecf1
    style USER fill:#1a1a2e,stroke:#10b981,color:#e8ecf1
    style MAIL fill:#1a1a2e,stroke:#ec4899,color:#e8ecf1
    style P1 fill:#0d1321,stroke:#00d4ff,color:#e8ecf1
    style P2 fill:#0d1321,stroke:#3b82f6,color:#e8ecf1
    style P3 fill:#0d1321,stroke:#f59e0b,color:#e8ecf1
    style P4 fill:#0d1321,stroke:#7c3aed,color:#e8ecf1
    style P5 fill:#0d1321,stroke:#ef4444,color:#e8ecf1
    style P6 fill:#0d1321,stroke:#10b981,color:#e8ecf1
    style P7 fill:#0d1321,stroke:#00d4ff,color:#e8ecf1
    style D1 fill:#1a1f2e,stroke:#00d4ff,color:#e8ecf1
    style D2 fill:#1a1f2e,stroke:#f59e0b,color:#e8ecf1
    style D3 fill:#1a1f2e,stroke:#7c3aed,color:#e8ecf1
    style D4 fill:#1a1f2e,stroke:#3b82f6,color:#e8ecf1
    style D5 fill:#1a1f2e,stroke:#7c3aed,color:#e8ecf1
    style D6 fill:#1a1f2e,stroke:#10b981,color:#e8ecf1
    style D7 fill:#1a1f2e,stroke:#10b981,color:#e8ecf1
```

### Data Flow Summary

| Flow | From | To | Data |
|------|------|----|------|
| 1 | Network | Packet Sniffer | Raw IP packets |
| 2 | Sniffer | Database | Parsed packet records |
| 3 | Sniffer | Analyzer | Packet stream for stats |
| 4 | Sniffer | Detectors | Packet stream for analysis |
| 5 | Analyzer | AI Engine | Feature vectors |
| 6 | Detectors | Alert Manager | Detection events |
| 7 | AI Engine | Alert Manager | Anomaly alerts |
| 8 | Alert Manager | Database | Alert records |
| 9 | Alert Manager | Email | Critical notifications |
| 10 | Database | Dashboard | Query results |
| 11 | Dashboard | User | HTML/JSON responses |
| 12 | User | Dashboard | Filter/action commands |
| 13 | Database | Report Gen | Historical data |
| 14 | Report Gen | Files | PDF/CSV reports |
