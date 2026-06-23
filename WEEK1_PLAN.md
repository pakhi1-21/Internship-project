# WEEK 1: Foundation Development & Core Infrastructure

## 🎯 Scope for Week 1
**Database persistence established, clean module imports, logging operational**

---

## 📅 Chronological Tasks

### **Day 1: Environment Preparation & System Configuration**

**Key Tasks:**
- [ ] Initialize Python 3.10+ isolated environment
  ```powershell
  python -m venv venv
  .\venv\Scripts\Activate.ps1
  ```
- [ ] Acquire all required `requirements.txt` components
  ```powershell
  pip install -r requirements.txt
  ```
- [ ] Establish `config.py` system variables
- [ ] Confirm Flask web server launches cleanly
  ```powershell
  python app.py
  ```

**Expected Output:** Operational Flask platform at `http://localhost:5000`

**Assessment Criteria:**
- [ ] Isolated Python environment active
- [ ] Package acquisition completes without issues
- [ ] Flask message: `Running on http://0.0.0.0:5000`
- [ ] Internet browser displays page without HTTP 500

---

### **Day 2: Database Architecture & Setup**

**Key Tasks:**
- [ ] Construct SQLite data structure with following collections:
  - `packets` (id, src_ip, dst_ip, src_port, dst_port, protocol, timestamp, size, flags)
  - `alerts` (id, alert_type, severity, description, src_ip, dst_ip, timestamp)
  - `anomalies` (id, threat_score, classification, timestamp, details)
  - `attacks` (id, attack_type, src_ip, target_info, details, timestamp)
  - `logs` (id, level, message, module, timestamp)

- [ ] Construct `backend/database.py` functionality:
  ```python
  def init_db()           # Establish all schema
  def insert_packet()     # Add packet entry
  def insert_alert()      # Add alert entry
  def get_alerts()        # Retrieve alert entries
  def cleanup_old_data()  # Purge entries >30 days old
  ```

- [ ] Perform database creation and retrieval operations

**Expected Output:** `database/netsight.db` established containing all 5 collections, successful initialization

**Assessment Criteria:**
- [ ] `database/netsight.db` present
- [ ] All 5 collections created
- [ ] `init_db()` executes successfully
- [ ] Data insertion and retrieval operations function

---

### **Day 3: Logging Infrastructure & Helper Programs**

**Key Tasks:**
- [ ] Establish `backend/logger.py`:
  ```python
  def get_system_logger()    # Furnish configured logging instance
  def setup_rotation()       # Configure 10MB per document, 5 retained versions
  ```

- [ ] Establish `backend/dns_resolver.py`:
  ```python
  def resolve_ip()           # Convert IP → domain resolution
  def batch_resolve()        # Resolve several IPs simultaneously
  ```

- [ ] Generate log directories:
  - `logs/system.log`
  - `logs/alerts.log`

- [ ] Confirm logging works across various components

**Expected Output:** Event logging functioning in `logs/` location appropriately

**Assessment Criteria:**
- [ ] `logs/system.log` established and receiving records
- [ ] `logs/alerts.log` created
- [ ] Rotation mechanism configured (10MB boundary)
- [ ] IP resolution performing properly

---

### **Day 4: Alerting & Message Infrastructure**

**Key Tasks:**
- [ ] Construct `backend/alert_manager.py`:
  ```python
  def create_alert()         # Formulate fresh alert entry
  def get_alerts()           # Get alerts with search capabilities
  def resolve_alert()        # Designate alert as handled
  def deduplicate_alerts()   # Avoid repeating alerts
  ```

- [ ] Construct `backend/email_alerts.py` outline:
  ```python
  def send_email()           # SMTP transmission apparatus (settings only, suppress actual delivery)
  def format_alert_email()   # Email structure
  ```

- [ ] Perform alert operations against persisted storage

**Expected Output:** Incident framework functional (add/retrieve/modify/remove alerts in storage)

**Assessment Criteria:**
- [ ] Alerts formulated via `create_alert()`
- [ ] Alerts retrieved via `get_alerts()`
- [ ] Alerts completed via `resolve_alert()`
- [ ] Alerts preserved in storage properly
- [ ] Repeat-prevention mechanism operates

---

### **Day 5: System-Wide Validation**

**Key Tasks:**
- [ ] Perform cross-module validation (storage → logging → incidents)
  ```python
  # Validation flow:
  1. init_db()
  2. Form trial alert
  3. Fetch alert
  4. Check logging activity
  5. Confirm IP resolution
  ```

- [ ] Ensure zero import issues in `app.py`
  ```powershell
  python -c "from app import app; print('OK')"
  ```

- [ ] Execute Flask platform and verify pathways:
  - `GET /` → dashboard.html responds
  - `GET /traffic` → traffic.html responds
  - Examine terminal for clean operation

- [ ] Record discovered complications

**Expected Output:** Trouble-free initialization, all system communications operational, Flask replying properly

**Assessment Criteria:**
- [ ] Flask begins with no alerts
- [ ] All 5 interface sections reply with OK status
- [ ] Database operations functional
- [ ] Event logs contain appropriate entries
- [ ] No package-loading alerts or runtime problems

---

## 📋 Progress Tracker - Week 1 Completion When:

```
Day 1 ✅
- [ ] Python sandbox made and engaged
- [ ] requirements.txt packages acquired
- [ ] Flask accessible on localhost:5000
- [ ] Zero alerts in command line

Day 2 ✅
- [ ] database/netsight.db created
- [ ] All 5 collections initialized
- [ ] init_db() finishes successfully
- [ ] Can store/retrieve trial information

Day 3 ✅
- [ ] logs/system.log exists and populated
- [ ] logs/alerts.log exists
- [ ] IP lookup procedures operational
- [ ] Size-based rotation functional

Day 4 ✅
- [ ] Incident addition/removal/modification functioning
- [ ] Incidents saved in storage
- [ ] Repeat-prevention logic operational
- [ ] Message transmission scaffolding complete

Day 5 ✅
- [ ] Flask launches cleanly
- [ ] All 5 interface areas accessible in navigation
- [ ] Storage retrieval functional
- [ ] No code-loading or performance issues
- [ ] Architecture prepared for Week 2
```

---

## 🚀 Upcoming Phases

Upon completion of Week 1, progress to **Week 2** to construct:
- Live packet acquisition (genuine stream capture)
- Reconnaissance method detector
- Credential assault detector

**Estimated Duration:** ~40 hours (5 shifts × 8 clock hours)

