# Architecture Diagram
## NetSight System Architecture

```mermaid
graph TB
    subgraph "Network Layer"
        NIC["Network Interface Card"]
        SIM["Simulation Engine"]
    end

    subgraph "Capture Layer"
        SNIFF["Packet Sniffer<br/>(AsyncSniffer)"]
        QUEUE["Packet Queue<br/>(Thread-Safe)"]
        WORKER["Packet Worker<br/>(Batch Processor)"]
    end

    subgraph "Storage Layer"
        DB["SQLite Database"]
        LOGS["Log Files<br/>(system.log / alerts.log)"]
        MODEL["AI Model<br/>(anomaly_model.pkl)"]
    end

    subgraph "Detection Layer"
        TA["Traffic Analyzer"]
        PSD["Port Scan<br/>Detector"]
        BFD["Brute Force<br/>Detector"]
        SAD["Suspicious Activity<br/>Detector"]
        AI["AI Detector<br/>(Isolation Forest)"]
    end

    subgraph "Management Layer"
        AM["Alert Manager"]
        RG["Report Generator"]
        EA["Email Alerts"]
    end

    subgraph "Presentation Layer"
        FLASK["Flask Server"]
        API["REST API<br/>(JSON Endpoints)"]
        DASH["Web Dashboard<br/>(Bootstrap 5 + Chart.js)"]
    end

    subgraph "Client"
        BROWSER["Web Browser"]
    end

    NIC --> SNIFF
    SIM --> SNIFF
    SNIFF --> QUEUE
    QUEUE --> WORKER

    WORKER --> DB
    WORKER --> TA
    WORKER --> PSD
    WORKER --> BFD
    WORKER --> SAD

    TA --> AI
    TA --> FLASK

    PSD --> AM
    BFD --> AM
    SAD --> AM
    AI --> AM

    AM --> DB
    AM --> LOGS
    AM --> EA

    AI --> MODEL
    AI --> DB

    RG --> DB

    FLASK --> API
    FLASK --> DASH
    API --> DB
    RG --> FLASK

    BROWSER --> DASH
    BROWSER --> API

    style NIC fill:#1a1a2e,stroke:#00d4ff,color:#e8ecf1
    style SIM fill:#1a1a2e,stroke:#7c3aed,color:#e8ecf1
    style SNIFF fill:#0d1321,stroke:#00d4ff,color:#e8ecf1
    style QUEUE fill:#0d1321,stroke:#00d4ff,color:#e8ecf1
    style WORKER fill:#0d1321,stroke:#00d4ff,color:#e8ecf1
    style DB fill:#1a1f2e,stroke:#10b981,color:#e8ecf1
    style LOGS fill:#1a1f2e,stroke:#10b981,color:#e8ecf1
    style MODEL fill:#1a1f2e,stroke:#10b981,color:#e8ecf1
    style TA fill:#0a0e17,stroke:#3b82f6,color:#e8ecf1
    style PSD fill:#0a0e17,stroke:#f59e0b,color:#e8ecf1
    style BFD fill:#0a0e17,stroke:#ef4444,color:#e8ecf1
    style SAD fill:#0a0e17,stroke:#fb923c,color:#e8ecf1
    style AI fill:#0a0e17,stroke:#7c3aed,color:#e8ecf1
    style AM fill:#1a1a2e,stroke:#f59e0b,color:#e8ecf1
    style RG fill:#1a1a2e,stroke:#10b981,color:#e8ecf1
    style EA fill:#1a1a2e,stroke:#ec4899,color:#e8ecf1
    style FLASK fill:#0d1321,stroke:#00d4ff,color:#e8ecf1
    style API fill:#0d1321,stroke:#00d4ff,color:#e8ecf1
    style DASH fill:#0d1321,stroke:#00d4ff,color:#e8ecf1
    style BROWSER fill:#1a1a2e,stroke:#e8ecf1,color:#e8ecf1
```

## Layer Descriptions

| Layer | Components | Purpose |
|-------|-----------|---------|
| **Network** | NIC, Simulation Engine | Raw packet source |
| **Capture** | AsyncSniffer, Queue, Worker | Reliable packet ingestion |
| **Storage** | SQLite, Logs, Model Files | Persistent data storage |
| **Detection** | Analyzers, Detectors, AI | Threat identification |
| **Management** | Alert Manager, Reports, Email | Alert lifecycle & reporting |
| **Presentation** | Flask, API, Dashboard | User interface |
