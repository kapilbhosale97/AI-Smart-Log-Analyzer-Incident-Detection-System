# 🛡️ AI Log Analyzer

> **Intelligent log analysis and incident detection powered by unsupervised machine learning and a deterministic rule engine — built with FastAPI.**

[![Python](https://img.shields.io/badge/Python-3.10%2B-3776AB?style=flat-square&logo=python&logoColor=white)](https://python.org)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.110%2B-009688?style=flat-square&logo=fastapi&logoColor=white)](https://fastapi.tiangolo.com)
[![scikit-learn](https://img.shields.io/badge/scikit--learn-1.4%2B-F7931E?style=flat-square&logo=scikit-learn&logoColor=white)](https://scikit-learn.org)
[![License: MIT](https://img.shields.io/badge/License-MIT-ec4899?style=flat-square)](LICENSE)

---

## 📋 Table of Contents

- [Overview](#-overview)
- [Features](#-features)
- [Architecture](#-architecture)
- [Project Structure](#-project-structure)
- [Getting Started](#-getting-started)
  - [Prerequisites](#prerequisites)
  - [Installation](#installation)
  - [Running the App](#running-the-app)
- [How It Works](#-how-it-works)
- [Log File Format](#-log-file-format)
- [API Reference](#-api-reference)
- [Configuration](#-configuration)
- [Screenshots](#-screenshots)
- [Roadmap](#-roadmap)
- [Contributing](#-contributing)
- [License](#-license)

---

## 🔍 Overview

**AI Log Analyzer** is a web application that ingests plain-text server/application log files and automatically detects anomalies and security incidents using two complementary layers:

| Layer | Method | Purpose |
|---|---|---|
| **ML Engine** | TF-IDF → SVD → Isolation Forest | Unsupervised anomaly detection on log messages |
| **Rule Engine** | Threshold-based pattern matching | Deterministic alerts for known threat patterns |

Upload a `.log`, `.txt`, or `.out` file through the browser and receive an instant analysis dashboard — no labelled training data required.

---

## ✨ Features

- **Unsupervised ML** — Automatically trains an Isolation Forest model on first upload; no labelled dataset needed
- **Real-time Analysis** — Results rendered instantly in a dark-mode dashboard
- **Rule-based Alerting** — Fires on high error rates, brute-force login attempts, warning storms, and critical events
- **Feature Extraction** — Counts errors, warnings, info, critical events, failed logins, and unique IP addresses
- **Flexible Log Parsing** — Supports multiple timestamp formats (`ISO-8601`, `YYYY-MM-DD HH:MM:SS`, bracketed levels)
- **Graceful Degradation** — Falls back cleanly when the model is not yet trained
- **Responsive UI** — Styled with Bootstrap 5 + custom dark theme; works on desktop and mobile

---

## 🏗️ Architecture

```
Browser (Upload)
      │
      ▼
┌─────────────────────────────────────────────────────┐
│                    FastAPI (main.py)                 │
│                                                      │
│  POST /analyze                                       │
│       │                                              │
│       ├─► log_parser.py       → List[LogDict]        │
│       ├─► feature_extraction.py → FeatureDict        │
│       ├─► rule_engine.py      → List[Alert]          │
│       └─► ml_model.py         → MLResult             │
│                                                      │
│  Jinja2 → dashboard.html                            │
└─────────────────────────────────────────────────────┘
      │
      ▼
Browser (Dashboard)
```

**ML Pipeline:**

```
Raw log messages
      │
      ▼
TfidfVectorizer  (max_features=200, sublinear_tf=True)
      │
      ▼
TruncatedSVD     (n_components=20)
      │
      ▼
IsolationForest  (contamination=0.05)
      │
      ▼
Anomaly score per log line  →  Aggregate prediction
```

---

## 📁 Project Structure

```
ai-log-analyzer/
│
├── app/
│   ├── __init__.py
│   ├── main.py                 # FastAPI app, routes, orchestration
│   ├── log_parser.py           # Regex-based log file parser
│   ├── feature_extraction.py   # Numerical feature extraction
│   ├── ml_model.py             # ML pipeline: train, load, predict
│   └── rule_engine.py          # Deterministic threshold-based rules
│
├── templates/
│   ├── index.html              # Upload page
│   └── dashboard.html          # Analysis results dashboard
│
├── logs/                       # Uploaded log files (auto-created, gitignored)
├── model/                      # Persisted model file (auto-created, gitignored)
│   └── advanced_model.pkl
│
├── requirements.txt
├── .gitignore
└── README.md
```

---

## 🚀 Getting Started

### Prerequisites

- Python **3.10** or higher
- `pip` package manager

### Installation

**1. Clone the repository**

```bash
git clone https://github.com/your-username/ai-log-analyzer.git
cd ai-log-analyzer
```

**2. Create and activate a virtual environment**

```bash
python -m venv venv

# macOS / Linux
source venv/bin/activate

# Windows
venv\Scripts\activate
```

**3. Install dependencies**

```bash
pip install -r requirements.txt
```

**`requirements.txt`**

```
fastapi>=0.110.0
uvicorn[standard]>=0.29.0
jinja2>=3.1.3
python-multipart>=0.0.9
scikit-learn>=1.4.0
joblib>=1.3.2
numpy>=1.26.0
```

### Running the App

```bash
uvicorn app.main:app --reload
```

Then open your browser and navigate to:

```
http://127.0.0.1:8000
```

> **Note:** The ML model trains automatically on the first file you upload. Subsequent uploads reuse the persisted model. To retrain, delete `model/advanced_model.pkl`.

---

## ⚙️ How It Works

### 1. Log Parsing (`log_parser.py`)

The parser uses a regex to handle multiple common log formats:

```
2024-01-15 12:34:56 ERROR  Database connection failed
[2024-01-15T12:34:56Z] [WARN] Disk usage at 85%
2024-01-15 12:35:01 INFO   Request processed in 42ms
```

Lines that don't match are parsed with a graceful whitespace-split fallback so no data is silently dropped.

### 2. Feature Extraction (`feature_extraction.py`)

Extracts the following structured features from the parsed log list:

| Feature | Description |
|---|---|
| `error_count` | Number of ERROR-level lines |
| `warn_count` | Number of WARN/WARNING-level lines |
| `info_count` | Number of INFO-level lines |
| `critical_count` | Number of CRITICAL-level lines |
| `failed_login_count` | Lines containing "failed login" or "authentication failure" |
| `error_ratio` | `error_count / total_logs` |
| `warn_ratio` | `warn_count / total_logs` |
| `unique_ip_count` | Count of unique IPv4 addresses found in messages |

### 3. Rule Engine (`rule_engine.py`)

Fires alerts when any threshold is breached:

| Rule | Default Threshold |
|---|---|
| High error count | ≥ 10 errors |
| High error ratio | ≥ 20% of all logs are errors |
| Brute-force risk | ≥ 5 failed login attempts |
| Warning storm | ≥ 40% of all logs are warnings |
| Critical event | Any CRITICAL-level log |
| IP diversity | > 20 unique IP addresses |

Thresholds are defined as constants at the top of `rule_engine.py` and can be tuned without touching logic.

### 4. ML Model (`ml_model.py`)

Uses a **fully unsupervised** pipeline — no labelled data required:

- `TfidfVectorizer` converts raw log message text into a sparse TF-IDF matrix
- `TruncatedSVD` reduces dimensionality to 20 components (configurable)
- `IsolationForest` assigns an anomaly score to each log message

A log file is flagged as **Anomaly** if more than **30%** of individual lines are scored as anomalous by the model.

> The trained pipeline is persisted to `model/advanced_model.pkl` via `joblib` and reloaded on subsequent requests — no retraining overhead on every upload.

---

## 📄 Log File Format

The parser supports files where each line follows this general pattern:

```
<TIMESTAMP> <LEVEL> <MESSAGE>
```

**Supported timestamp formats:**

```
2024-01-15 12:34:56
2024-01-15T12:34:56Z
2024-01-15T12:34:56+05:30
[2024-01-15 12:34:56]
```

**Supported log levels:**

`ERROR` · `WARN` · `WARNING` · `INFO` · `DEBUG` · `CRITICAL` · `NOTICE` · `FATAL`

**Accepted file extensions:** `.log` · `.txt` · `.out`

**Example log file:**

```
2024-01-15 08:00:01 INFO  Application started successfully
2024-01-15 08:01:14 WARN  Memory usage at 78%
2024-01-15 08:03:22 ERROR Failed to connect to database: timeout
2024-01-15 08:03:45 ERROR Failed login attempt from 192.168.1.105
2024-01-15 08:03:46 ERROR Failed login attempt from 192.168.1.105
2024-01-15 08:03:47 ERROR Failed login attempt from 192.168.1.105
2024-01-15 08:05:00 CRITICAL Disk partition /var is full
```

---

## 🌐 API Reference

### `GET /`

Returns the upload page (`index.html`).

---

### `POST /analyze`

Accepts a multipart form upload and returns the analysis dashboard.

**Request**

| Field | Type | Required | Description |
|---|---|---|---|
| `file` | `UploadFile` | ✅ | Log file (`.log`, `.txt`, `.out`) |

**Success Response**

Returns `text/html` — the rendered `dashboard.html` template.

**Error Responses**

| Status | Reason |
|---|---|
| `400` | Unsupported file type, unreadable file, or no parseable log entries |
| `500` | Server-side file write failure |

---

## 🔧 Configuration

Key parameters are defined as module-level constants for easy tuning:

**`app/ml_model.py`**

```python
# Called from main.py — override these in train_model() call if needed
max_features   = 200    # TF-IDF vocabulary size
svd_components = 20     # Latent dimensions after SVD
contamination  = 0.05   # Expected fraction of anomalies (0.0–0.5)
```

**`app/rule_engine.py`**

```python
_ERROR_THRESHOLD        = 10     # Absolute error count
_ERROR_RATIO_THRESHOLD  = 0.20   # 20% of logs are errors
_FAILED_LOGIN_THRESHOLD = 5      # Failed login attempts
_CRITICAL_THRESHOLD     = 1      # Any CRITICAL fires an alert
_WARN_RATIO_THRESHOLD   = 0.40   # 40% of logs are warnings
```

**`app/main.py`**

```python
_ALLOWED_EXTENSIONS = {".log", ".txt", ".out"}   # Accepted file types
UPLOAD_DIR          = "logs"                      # Upload directory
```

---

## 🗺️ Roadmap

- [ ] **Incremental training** — update the model without full retraining on new data
- [ ] **Log streaming** — real-time tail and analysis of live log files
- [ ] **Export** — download analysis report as PDF or JSON
- [ ] **Multi-file comparison** — diff anomaly patterns across multiple log files
- [ ] **Custom rule builder** — define rules via the UI without editing code
- [ ] **Persistent history** — store past analysis runs in SQLite
- [ ] **Docker support** — `Dockerfile` and `docker-compose.yml`
- [ ] **Unit tests** — pytest coverage for parser, extractor, and rule engine

---

## 🤝 Contributing

Contributions are welcome! Here's how to get started:

```bash
# 1. Fork the repo and clone your fork
git clone https://github.com/chirdekaran262/Log-analyzer-AI.git

# 2. Create a feature branch
git checkout -b feature/your-feature-name

# 3. Make your changes and commit
git commit -m "feat: add your feature description"

# 4. Push and open a Pull Request
git push origin feature/your-feature-name
```

Please follow [Conventional Commits](https://www.conventionalcommits.org/) for commit messages and keep PRs focused on a single concern.

---

## 📄 License

This project is licensed under the **MIT License**. See [LICENSE](LICENSE) for details.

---

<div align="center">
  Built with FastAPI · scikit-learn · Chart.js · Bootstrap 5
</div>
