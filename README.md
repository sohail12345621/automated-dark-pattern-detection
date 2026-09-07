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

- **Selenium**: Enables dynamic DOM rendering and automated UI element extraction.
- **Scikit-Learn**: Implements text classification without external cloud API costs.
- **TF-IDF**: Converts natural language UI text into numerical feature vectors.
- **Logistic Regression**: Provides a fast, interpretable baseline classifier with probability scores.
- **Rule Engine**: Handles deterministic UI properties like pre-selected checkboxes.
- **Hybrid Detection**: Merges deterministic DOM rules with ML predictions for superior accuracy.
- **Evidence Engine**: Delivers explainable, reproducible evidence for every flagged dark pattern.

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
├── config/             # App & Database configuration
├── crawler/            # Selenium scanner & DOM extractor
├── detector/           # Rule engine, ML classifier, Evidence engine
├── database/           # MySQL persistence with SQLite fallback
├── ml/                 # ML dataset, training script, model binaries
│   └── models/
├── templates/          # HTML templates (Scanner, Results, History)
├── static/             # CSS & JS assets
│   ├── css/
│   └── js/
├── screenshots/        # Captured evidence screenshots
├── demo_site/          # Local test harness page
├── tests/              # Unit and integration test suite
├── app.py              # Main Flask web application
├── requirements.txt    # Project dependencies
└── README.md           # Documentation
```

---

## 📄 License
Academic Project Based Learning (PBL) Prototype.
