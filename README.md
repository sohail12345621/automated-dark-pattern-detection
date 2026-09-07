# Automated Dark Pattern Identification and UI Deception Analysis System with Evidence-Based Detection

A College Project Based Learning (PBL) prototype designed to automatically scan web pages, detect dark UI patterns using a hybrid approach (DOM/UI rules + TF-IDF Logistic Regression ML), capture evidence/screenshots, and present actionable findings via an interactive Flask dashboard.

---

## 📌 Project Objectives

1. **Automated Webpage Scanning**: Use Selenium to render web pages and extract visible text, interactive elements (buttons, links, forms, checkboxes).
2. **Dark Pattern Classification**: Classify UI elements into core categories:
   - Urgency
   - Scarcity
   - Confirmshaming
   - Forced Action
   - Preselection
3. **Evidence-Based Detection**: Provide explicit justification for flagged elements including text, HTML snippet, severity, confidence score, and screenshots.
4. **Local Persistence**: Store scan history and evidence transparently in MySQL.

---

## 🛠 Tech Stack

- **Backend**: Python 3.14, Flask
- **Browser Automation**: Selenium WebDriver
- **Machine Learning**: Scikit-learn (TF-IDF + Logistic Regression)
- **Database**: MySQL
- **Frontend**: HTML5, CSS3, JavaScript

---

## 📁 Directory Structure

```text
automated-dark-pattern-detection/
├── config/             # Environment and app configuration
├── crawler/            # Selenium web scanner
├── detector/           # Detection engine (Rules, ML, Evidence)
├── database/           # MySQL persistence layer
├── ml/                 # ML dataset and training scripts
│   └── models/         # Trained model binaries
├── templates/          # Flask HTML templates
├── static/             # CSS / JS static assets
│   ├── css/
│   └── js/
├── screenshots/        # Captured element/page evidence
├── demo_site/          # Local test page with dark pattern examples
├── tests/              # Unit and integration tests
├── app.py              # Main Flask entry point
├── requirements.txt    # Project dependencies
└── README.md
```

---

## 🚀 Getting Started

### Prerequisites
- Python 3.10+
- MySQL Server
- Google Chrome / ChromeDriver

### Installation
1. Clone the repository:
   ```bash
   git clone https://github.com/sohail12345621/automated-dark-pattern-detection.git
   cd automated-dark-pattern-detection
   ```
2. Set up virtual environment & install dependencies:
   ```bash
   python -m venv venv
   venv\Scripts\activate
   pip install -r requirements.txt
   ```
3. Configure environment variables:
   ```bash
   cp .env.example .env
   # Update database credentials in .env
   ```

---

## 📄 License
Academic PBL / Open-Source Project.
