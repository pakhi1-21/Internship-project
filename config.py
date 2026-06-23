"""
NetSight - Configuration Module
=====================================
Central configuration for all system parameters including detection thresholds,
database paths, Flask settings, AI model parameters, and email configuration.
"""

import os

# ============================================================
# BASE PATHS
# ============================================================
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATABASE_DIR = os.path.join(BASE_DIR, 'database')
LOGS_DIR = os.path.join(BASE_DIR, 'logs')
REPORTS_DIR = os.path.join(BASE_DIR, 'reports')
MODELS_DIR = os.path.join(BASE_DIR, 'models')

# Create directories if they don't exist
for directory in [DATABASE_DIR, LOGS_DIR, REPORTS_DIR, MODELS_DIR]:
    os.makedirs(directory, exist_ok=True)

# ============================================================
# DATABASE
# ============================================================
DATABASE_PATH = os.path.join(DATABASE_DIR, 'netsight.db')

# Data retention: delete records older than N days
DATA_RETENTION_DAYS = 30

# ============================================================
# FLASK
# ============================================================
FLASK_HOST = '0.0.0.0'
FLASK_PORT = 5000
FLASK_DEBUG = True
SECRET_KEY = 'ns-s3cur3-k3y-ch4ng3-1n-pr0duct10n-2024!'

# ============================================================
# LOGGING
# ============================================================
SYSTEM_LOG_FILE = os.path.join(LOGS_DIR, 'netsight_system.log')
ALERTS_LOG_FILE = os.path.join(LOGS_DIR, 'netsight_alerts.log')
LOG_MAX_BYTES = 10 * 1024 * 1024  # 10 MB per log file
LOG_BACKUP_COUNT = 5  # Keep 5 rotated log files

# ============================================================
# PACKET CAPTURE
# ============================================================
# Network interface to capture on (None = auto-detect default)
CAPTURE_INTERFACE = None

# BPF filter for packet capture (empty = capture all)
CAPTURE_FILTER = 'ip'

# Batch size for database inserts
PACKET_BATCH_SIZE = 50

# Batch timeout in seconds (flush even if batch not full)
PACKET_BATCH_TIMEOUT = 2.0

# Enable simulation mode (synthetic traffic when Npcap unavailable)
SIMULATION_MODE = False  # Npcap detected — using live capture

# Simulation packets per second
SIMULATION_PPS = 15

# ============================================================
# PORT SCAN DETECTION
# ============================================================
PORT_SCAN_THRESHOLD = 20          # Number of unique ports to trigger alert
PORT_SCAN_TIME_WINDOW = 10        # Seconds to track port access
PORT_SCAN_SYN_ONLY = True         # Also detect SYN-only scans
PORT_SCAN_SEQUENTIAL_GAP = 5      # Max gap between ports for sequential detection

# ============================================================
# BRUTE FORCE DETECTION
# ============================================================
BRUTE_FORCE_THRESHOLD = 10        # Connection attempts to trigger alert
BRUTE_FORCE_TIME_WINDOW = 60      # Seconds to track attempts
BRUTE_FORCE_COOLDOWN = 300        # Seconds before re-alerting same IP

# Monitored service ports
BRUTE_FORCE_PORTS = {
    22: 'SSH',
    23: 'Telnet',
    21: 'FTP',
    3389: 'RDP',
    3306: 'MySQL',
    5432: 'PostgreSQL',
    1433: 'MSSQL',
    27017: 'MongoDB',
    6379: 'Redis',
    8080: 'HTTP-Proxy',
    443: 'HTTPS',
    80: 'HTTP',
    25: 'SMTP',
    110: 'POP3',
    143: 'IMAP',
}

# ============================================================
# SUSPICIOUS ACTIVITY DETECTION
# ============================================================
SPIKE_STD_MULTIPLIER = 3.0        # Traffic spike = mean + N * std_dev
SINGLE_IP_PACKET_RATE = 100       # Max packets/sec from single IP
SINGLE_IP_DEST_LIMIT = 50         # Max unique destinations from single IP
EXCESSIVE_PACKET_THRESHOLD = 1000 # Max packets from single IP in time window
EXCESSIVE_PACKET_WINDOW = 60      # Time window in seconds

# ============================================================
# AI ANOMALY DETECTION
# ============================================================
AI_MODEL_PATH = os.path.join(MODELS_DIR, 'anomaly_model.pkl')
AI_SCALER_PATH = os.path.join(MODELS_DIR, 'scaler.pkl')
AI_CONTAMINATION = 0.1            # Isolation Forest contamination parameter
AI_N_ESTIMATORS = 100             # Number of trees in Isolation Forest
AI_MIN_SAMPLES = 100              # Min samples before training
AI_ANALYSIS_INTERVAL = 30         # Seconds between AI analysis runs
AI_FEATURE_WINDOW = 60            # Seconds of data to compute features from

# Threat score thresholds
THREAT_SCORE_NORMAL = 30          # 0–30: Normal
THREAT_SCORE_SUSPICIOUS = 70      # 31–70: Suspicious
# 71–100: Malicious

# ============================================================
# ALERT MANAGEMENT
# ============================================================
ALERT_DEDUP_WINDOW = 300          # Seconds to suppress duplicate alerts
MAX_ALERTS_DISPLAY = 100          # Max alerts shown in dashboard

# Severity levels
SEVERITY_LOW = 'LOW'
SEVERITY_MEDIUM = 'MEDIUM'
SEVERITY_HIGH = 'HIGH'
SEVERITY_CRITICAL = 'CRITICAL'

# Alert types
ALERT_PORT_SCAN = 'PORT_SCAN'
ALERT_BRUTE_FORCE = 'BRUTE_FORCE'
ALERT_TRAFFIC_SPIKE = 'TRAFFIC_SPIKE'
ALERT_AI_ANOMALY = 'AI_ANOMALY'
ALERT_SUSPICIOUS = 'SUSPICIOUS_ACTIVITY'

# ============================================================
# REPORT GENERATION
# ============================================================
REPORT_COMPANY_NAME = 'NetSight Security'
REPORT_TIMEZONE = 'Asia/Kolkata'

# ============================================================
# EMAIL ALERTS (Optional)
# ============================================================
EMAIL_ENABLED = False
SMTP_SERVER = 'smtp.gmail.com'
SMTP_PORT = 587
SMTP_USE_TLS = True
SMTP_USERNAME = ''
SMTP_PASSWORD = ''
EMAIL_FROM = ''
EMAIL_RECIPIENTS = []
EMAIL_RATE_LIMIT = 900            # Seconds between emails per alert type

# ============================================================
# DETECTION ENGINE INTERVALS
# ============================================================
DETECTION_INTERVAL = 5            # Seconds between detection engine runs
STATS_UPDATE_INTERVAL = 1         # Seconds between stats updates
CLEANUP_INTERVAL = 3600           # Seconds between database cleanup runs
