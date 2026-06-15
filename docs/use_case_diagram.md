# Use Case Diagram
## NetSight Use Cases

```mermaid
graph LR
    subgraph "Actors"
        SA["🧑‍💻 Security Analyst"]
        SYS["⚙️ System (Automated)"]
        NET["🌐 Network"]
    end

    subgraph "NetSight System"
        UC1["View Dashboard"]
        UC2["Monitor Live Traffic"]
        UC3["View Security Alerts"]
        UC4["Resolve Alerts"]
        UC5["View Analytics Charts"]
        UC6["Generate Reports"]
        UC7["Download Reports"]
        UC8["Start/Stop Capture"]
        UC9["Filter Traffic Data"]
        UC10["Filter Alerts"]

        UC11["Capture Packets"]
        UC12["Analyze Traffic"]
        UC13["Detect Port Scans"]
        UC14["Detect Brute Force"]
        UC15["Detect Suspicious Activity"]
        UC16["AI Anomaly Detection"]
        UC17["Generate Alerts"]
        UC18["Send Email Notifications"]
        UC19["Train AI Model"]
        UC20["Cleanup Old Data"]
        UC21["Log Events"]
    end

    SA --> UC1
    SA --> UC2
    SA --> UC3
    SA --> UC4
    SA --> UC5
    SA --> UC6
    SA --> UC7
    SA --> UC8
    SA --> UC9
    SA --> UC10

    NET --> UC11
    SYS --> UC11
    SYS --> UC12
    SYS --> UC13
    SYS --> UC14
    SYS --> UC15
    SYS --> UC16
    SYS --> UC17
    SYS --> UC18
    SYS --> UC19
    SYS --> UC20
    SYS --> UC21

    UC11 --> UC12
    UC12 --> UC13
    UC12 --> UC14
    UC12 --> UC15
    UC12 --> UC16
    UC13 --> UC17
    UC14 --> UC17
    UC15 --> UC17
    UC16 --> UC17
    UC17 --> UC18

    style SA fill:#1a1a2e,stroke:#10b981,color:#e8ecf1
    style SYS fill:#1a1a2e,stroke:#7c3aed,color:#e8ecf1
    style NET fill:#1a1a2e,stroke:#00d4ff,color:#e8ecf1

    style UC1 fill:#0d1321,stroke:#00d4ff,color:#e8ecf1
    style UC2 fill:#0d1321,stroke:#00d4ff,color:#e8ecf1
    style UC3 fill:#0d1321,stroke:#00d4ff,color:#e8ecf1
    style UC4 fill:#0d1321,stroke:#00d4ff,color:#e8ecf1
    style UC5 fill:#0d1321,stroke:#00d4ff,color:#e8ecf1
    style UC6 fill:#0d1321,stroke:#00d4ff,color:#e8ecf1
    style UC7 fill:#0d1321,stroke:#00d4ff,color:#e8ecf1
    style UC8 fill:#0d1321,stroke:#00d4ff,color:#e8ecf1
    style UC9 fill:#0d1321,stroke:#00d4ff,color:#e8ecf1
    style UC10 fill:#0d1321,stroke:#00d4ff,color:#e8ecf1

    style UC11 fill:#0d1321,stroke:#7c3aed,color:#e8ecf1
    style UC12 fill:#0d1321,stroke:#7c3aed,color:#e8ecf1
    style UC13 fill:#0d1321,stroke:#f59e0b,color:#e8ecf1
    style UC14 fill:#0d1321,stroke:#ef4444,color:#e8ecf1
    style UC15 fill:#0d1321,stroke:#fb923c,color:#e8ecf1
    style UC16 fill:#0d1321,stroke:#7c3aed,color:#e8ecf1
    style UC17 fill:#0d1321,stroke:#f59e0b,color:#e8ecf1
    style UC18 fill:#0d1321,stroke:#ec4899,color:#e8ecf1
    style UC19 fill:#0d1321,stroke:#7c3aed,color:#e8ecf1
    style UC20 fill:#0d1321,stroke:#10b981,color:#e8ecf1
    style UC21 fill:#0d1321,stroke:#10b981,color:#e8ecf1
```

## Use Case Descriptions

### Actor: Security Analyst (Human)

| Use Case | Description | Precondition | Postcondition |
|----------|-------------|--------------|---------------|
| UC1: View Dashboard | View real-time stats, threat score, AI status | App running | Dashboard displayed with current data |
| UC2: Monitor Live Traffic | View packet capture in real-time | Capture running | Traffic table updated every 2s |
| UC3: View Security Alerts | Browse and filter alerts by type/severity | Alerts exist | Alert list displayed |
| UC4: Resolve Alerts | Mark an alert as resolved | Alert is active | Alert status changed to resolved |
| UC5: View Analytics | Explore traffic charts and attack trends | Data collected | Charts rendered with current data |
| UC6: Generate Reports | Trigger PDF/CSV report generation | Data exists | Report files created |
| UC7: Download Reports | Download generated report files | Reports exist | File downloaded to local machine |
| UC8: Start/Stop Capture | Control packet capture engine | App running | Capture state toggled |
| UC9: Filter Traffic | Apply protocol/IP filters to traffic view | Traffic data exists | Filtered results displayed |
| UC10: Filter Alerts | Apply type/severity filters to alert view | Alerts exist | Filtered alerts displayed |

### Actor: System (Automated)

| Use Case | Description | Trigger | Postcondition |
|----------|-------------|---------|---------------|
| UC11: Capture Packets | Capture network packets continuously | Capture started | Packets stored in database |
| UC12: Analyze Traffic | Compute traffic statistics | Every 1 second | Stats updated |
| UC13: Detect Port Scans | Identify port scanning patterns | Packet received | Alert generated if scan detected |
| UC14: Detect Brute Force | Identify brute force attempts | TCP SYN to service port | Alert generated if threshold exceeded |
| UC15: Detect Suspicious | Identify anomalous traffic patterns | Every 5 seconds | Threat score updated |
| UC16: AI Detection | Run Isolation Forest prediction | Every 30 seconds | Anomaly result stored |
| UC17: Generate Alerts | Create and store security alerts | Detection event | Alert stored and logged |
| UC18: Send Emails | Notify on HIGH/CRITICAL alerts | HIGH/CRITICAL alert | Email sent to recipients |
| UC19: Train AI Model | Auto-train on baseline data | 100+ samples collected | Model saved to disk |
| UC20: Cleanup Data | Remove old records | Every 1 hour | Old records deleted |
| UC21: Log Events | Record system and alert events | Any event | Log entries written |
