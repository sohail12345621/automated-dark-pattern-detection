# Automated Dark Pattern Identification and User Interface Deception Analysis System with Evidence-Based Detection

A College Project Based Learning (PBL) prototype designed to automatically scan web pages, extract interactive DOM elements, detect dark UI patterns using a hybrid detection architecture (DOM Rules + Scikit-Learn ML), capture evidence screenshots, and present actionable findings via an interactive Flask dashboard.

---

## 📌 Problem Statement & Objectives

Modern e-commerce and web platforms frequently employ deceptive UI designs known as **Dark Patterns** (e.g., fake urgency timers, scarcity stock alerts, pre-selected opt-ins, confirmshaming copy) that manipulate users into unintended actions.

### Objectives
1. **Automated Webpage Scanning**: Use headless Selenium to open pages, wait for dynamic DOM rendering, extract visible textual content, buttons, links, forms, and checkboxes.
2. **Dark Pattern Classification**: Detect core pattern categories:
   - **Urgency** (time pressure banners, expiring offer warnings)
   - **Scarcity** (artificial low stock alerts)
   - **Confirmshaming** (guilt-inducing opt-out copy)
   - **Forced Action** (unwanted mandatory marketing prerequisites)
   - **Preselection** (pre-checked optional checkboxes)
3. **Evidence-Based Detection**: Provide explicit, traceable evidence answering *"Why was this UI element flagged?"* including confidence scores, severity levels, HTML snippets, explanations, and screenshots.
4. **Local Persistence**: Store full evaluation history and evidence transparently in MySQL / SQLite.

---

## 🏗 Architecture & Hybrid Detection System

```text
                        Target URL
                            │
                            ▼
                    Selenium Scanner
              (DOM & Attribute Extraction)
                            │
            ┌───────────────┴───────────────┐
            ▼                               ▼
     Rule Engine                    ML Classifier
  (Heuristic Patterns)          (TF-IDF + Logistic Reg)
            │                               │
            └───────────────┬───────────────┘
                            ▼
                  Hybrid Result Fusion
                            │
                            ▼
                    Evidence Engine
              (Explanation & Screenshots)
                            │
            ┌───────────────┴───────────────┐
            ▼                               ▼
     MySQL / SQLite                  Flask Dashboard
   Persistent Storage             (Results & History)
```

---

## 🛠 Tech Stack

- **Backend**: Python 3.14, Flask
- **Browser Automation**: Selenium WebDriver (Headless Chrome)
- **Machine Learning**: Scikit-Learn (TF-IDF Vectorizer + Logistic Regression)
- **Database**: MySQL (with automatic zero-downtime SQLite fallback)
- **Frontend**: HTML5, CSS3, JavaScript (Academic UI design)

---

## 🚀 Quick Start Guide

### 1. Prerequisites
- Python 3.10+
- Google Chrome browser
- MySQL Server (Optional, auto-falls back to SQLite if unconfigured)

### 2. Installation
```bash
git clone https://github.com/sohail12345621/automated-dark-pattern-detection.git
cd automated-dark-pattern-detection
pip install -r requirements.txt
```

### 3. Environment Setup
Create a `.env` file based on `.env.example`:
```env
DB_HOST=127.0.0.1
DB_PORT=3306
DB_USER=root
DB_PASSWORD=
DB_NAME=dark_pattern_db
FLASK_ENV=development
SECRET_KEY=dev-secret-key
```

### 4. Running the ML Training Pipeline (Optional)
To retrain the ML classifier locally:
```bash
python ml/train_model.py
```

### 5. Running the Application
Start the Flask web server:
```bash
python app.py
```
Open your browser at `http://127.0.0.1:5000`.

### 6. Testing Against the Local Test Harness
- Click **"🎯 Use Local Demo Webpage"** on the dashboard (or enter `http://127.0.0.1:5000/demo`).
- Click **"Scan Website"** to execute Selenium scanning and view evidence results.

---

## 🧪 Running Automated Tests

Run the full unit and integration test suite:
```bash
python -m unittest discover tests
```

---

## 🎓 Academic Viva & Evaluation Justification

- **URL Validator & SSRF Prevention**: Defends scanning infrastructure against server-side request forgery to private subnets or cloud metadata endpoints.
- **Security Rule Engine**: Detects deceptive and vulnerable UI structures (insecure form submission, clickjacking overlays, anchor phishing) that purely textual NLP models miss.
- **Security Headers & TLS Inspection**: Validates defense-in-depth posture (HSTS, CSP, XFO, valid certs) to protect users from downgrade attacks and clickjacking.
- **Third-Party Tracker Inventory**: Audits surveillance capitalism telemetry and privacy leakage without external paid threat-intel APIs.
- **Composite Domain Risk Score**: Provides a standardized 0-100 metric combining visual manipulation with defensive security health for unified risk posture.
- **Selenium**: Enables dynamic DOM rendering and automated UI element extraction.
- **Scikit-Learn**: Implements text classification without external cloud API costs.
- **TF-IDF**: Converts natural language UI text into numerical feature vectors.
- **Logistic Regression**: Provides a fast, interpretable baseline classifier with probability scores.
- **Rule Engine**: Handles deterministic UI properties like pre-selected checkboxes.
- **Hybrid Detection**: Merges deterministic DOM rules with ML predictions for superior accuracy.
- **Evidence Engine**: Delivers explainable, reproducible evidence for every flagged dark pattern.

---


---

## 🔒 Defensive Security Architecture & Domain Risk Scoring

This project integrates defensive cybersecurity inspection with UI deception analysis:

### 1. Scanner Hardening & SSRF Protection
- **SSRF URL Validator (`security/url_validator.py`)**: Resolves target hostnames and blocks private (RFC 1918), loopback, link-local, and cloud metadata IP addresses (`169.254.169.254`). Rejects embedded credentials in URLs and enforces strict length boundaries.
- **Restricted Chrome Profile (`crawler/selenium_scanner.py`)**: Employs disposable temporary user-data directories, blocks file downloads, runs headless sandbox flags, and enforces page-load and command timeouts.
- **Web Hardening (`app.py`)**: Implements scan-form CSRF validation, per-IP rate limiting (10 scans/minute), secure session cookies (`HttpOnly`, `SameSite=Lax`), and strict HTTP security headers (`CSP`, `X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff`).

### 2. Deceptive-UI Security Rules (`detector/security_rules.py`)
- **Insecure Form Submissions**: Flags HTML `<form>` or `<input>` fields that transmit sensitive credentials or PII over unencrypted `http://` actions.
- **Hidden / Overlay Deception**: Flags zero-opacity (`opacity: 0`), invisible, or off-screen `<iframe>` elements and buttons indicative of UI redressing and clickjacking.
- **Deceptive Links**: Detects phishing-style link text where visible anchor text shows a trusted domain while the actual `href` targets an external domain, as well as IDN homograph punycode patterns.
- **Cookie Consent Manipulation**: Flags asymmetrical consent banners that promote "Accept All" while obscuring or eliminating balanced "Reject All" alternatives.
- **Excessive Permission Prompts**: Detects scripts invoking browser notifications (`Notification.requestPermission`) or location without preceding user gestures.

### 3. Transport, Headers & Tracker Inventory (`detector/security_headers.py`)
- **Security Headers Inspection**: Verifies mandatory defense-in-depth headers: HSTS (`Strict-Transport-Security`), CSP (`Content-Security-Policy`), `X-Frame-Options`, `X-Content-Type-Options`, and `Referrer-Policy`.
- **TLS Certificate Analysis**: Verifies HTTPS encryption status, certificate validity, expiration dates, and untrusted certificate authority warnings via standard `ssl`/`socket`.
- **Third-Party Tracker Inventory (`detector/trackers.json`)**: Audits all external scripts and iframes against a curated database of 30+ major surveillance capitalism and analytics tracking domains.

### 4. 0–100 Composite Domain Risk Score Calculation
Configured transparently in `config/config.py` (`RISK_WEIGHTS`):
- **Dark Patterns**: High (+15), Medium (+8), Low (+3)
- **Missing Security Headers**: +5 per missing defense header
- **Transport Security**: Plaintext HTTP (+20), Expired/Invalid TLS Cert (+25)
- **Trackers**: Known telemetry network (+10), Third-party script (+2)
- **Risk Tiers**: 0–25 (LOW), 26–50 (MEDIUM), 51–75 (HIGH), 76–100 (CRITICAL)


---

## 🔮 Future Scope (Final Year Project Foundation)

- Expanding dataset with deep NLP (Transformers / BERT).
- Computer vision model for layout deception analysis.
- Multi-page crawling and domain risk scoring.
- Browser extension for real-time user protection.

---

## 📁 Repository Structure

```text
automated-dark-pattern-detection/
├── config/             # App & Database configuration (risk weights, DB settings)
├── crawler/            # Hardened Selenium scanner & DOM extractor
├── detector/           # Rules, ML classifier, Evidence engine, Security rules/headers/trackers
├── database/           # Safe MySQL persistence with SQLite fallback
├── security/           # SSRF URL validator and IP protection
├── ml/                 # ML dataset, training script, model binaries
│   └── models/
├── templates/          # HTML templates (Scanner, Results, History)
├── static/             # CSS & JS assets
│   ├── css/
│   └── js/
├── screenshots/        # Captured evidence screenshots
├── demo_site/          # Local test harness with deceptive pattern cases
├── tests/              # Unit and integration test suite
├── app.py              # Main Flask web application
├── requirements.txt    # Project dependencies
└── README.md           # Documentation
```

---

## 📄 License
Academic Project Based Learning (PBL) Prototype.
