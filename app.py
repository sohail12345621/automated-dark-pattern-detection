import os
import time
from functools import wraps
from datetime import datetime
from flask import Flask, render_template, request, redirect, url_for, flash, session, send_from_directory
from werkzeug.security import generate_password_hash, check_password_hash
from config.config import Config
from crawler.selenium_scanner import SeleniumScanner
from detector.evidence import EvidenceEngine
from database.db import DatabaseManager

app = Flask(__name__)
app.config.from_object(Config)

# Secure Session Configuration
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
app.config["PERMANENT_SESSION_LIFETIME"] = 3600

# Ensure required runtime directories exist
os.makedirs(Config.SCREENSHOTS_DIR, exist_ok=True)

# Initialize persistent database manager and detector engines
db_manager = DatabaseManager()
evidence_engine = EvidenceEngine()
scanner = SeleniumScanner(headless=True, timeout=15)

# In-Memory Brute-Force Login Protection Tracker
FAILED_LOGINS = {}  # { username: {"count": int, "lockout_until": float} }

def seed_default_admin():
    """Seeds default admin account (admin / admin123) if no users exist."""
    try:
        existing_admin = db_manager.get_user_by_username("admin")
        if not existing_admin:
            pwd_hash = generate_password_hash("admin123")
            db_manager.create_user("admin", "admin@darkpatterns.local", pwd_hash, role="ADMIN")
            print("[Database] Default admin user initialized (admin / admin123).")
    except Exception as e:
        print(f"[Database Warning] Failed to seed default admin: {e}")

seed_default_admin()

# --- RBAC DECORATORS ---
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if "user_id" not in session:
            flash("Please log in to access this feature.", "info")
            return redirect(url_for("login"))
        return f(*args, **kwargs)
    return decorated_function

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if "user_id" not in session:
            flash("Please log in as Administrator.", "info")
            return redirect(url_for("login"))
        if session.get("role") != "ADMIN":
            flash("Access Denied: Administrator privileges required.", "error")
            return redirect(url_for("index")), 403
        return f(*args, **kwargs)
    return decorated_function

# --- AUTHENTICATION ROUTES ---
@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        email = request.form.get("email", "").strip()
        password = request.form.get("password", "")
        confirm_password = request.form.get("confirm_password", "")
        ip_addr = request.remote_addr or "127.0.0.1"

        if not username or not email or not password:
            flash("All fields are required.", "error")
            return render_template("register.html")

        if len(password) < 6:
            flash("Password must be at least 6 characters long.", "error")
            return render_template("register.html")

        if password != confirm_password:
            flash("Passwords do not match.", "error")
            return render_template("register.html")

        if db_manager.get_user_by_username(username):
            flash("Username already taken. Please choose another.", "error")
            return render_template("register.html")

        password_hash = generate_password_hash(password)
        # Assign ADMIN to first non-default user if needed, else USER
        role = "USER"

        user_id = db_manager.create_user(username, email, password_hash, role=role)
        if user_id:
            db_manager.log_audit_event(user_id, username, "REGISTER", status="SUCCESS", ip_address=ip_addr, details="New account created")
            flash("Registration successful! Please log in with your credentials.", "info")
            return redirect(url_for("login"))
        else:
            db_manager.log_audit_event(None, username, "REGISTER", status="FAILED", ip_address=ip_addr, details="Integrity error")
            flash("Registration failed. Username or email may already be registered.", "error")

    return render_template("register.html")

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        ip_addr = request.remote_addr or "127.0.0.1"
        now = time.time()

        # Brute-Force Lockout Check
        tracker = FAILED_LOGINS.get(username, {"count": 0, "lockout_until": 0})
        if tracker["lockout_until"] > now:
            remaining = int(tracker["lockout_until"] - now)
            db_manager.log_audit_event(None, username, "LOGIN_FAILED", status="BLOCKED", ip_address=ip_addr, details=f"Locked out for {remaining}s")
            flash(f"Account temporarily locked due to multiple failed attempts. Please try again in {remaining} seconds.", "error")
            return render_template("login.html")

        user = db_manager.get_user_by_username(username)
        if user and check_password_hash(user["password_hash"], password):
            # Reset failed login counter on success
            FAILED_LOGINS[username] = {"count": 0, "lockout_until": 0}
            session.permanent = True
            session["user_id"] = user["id"]
            session["username"] = user["username"]
            session["role"] = user["role"]

            db_manager.log_audit_event(user["id"], user["username"], "LOGIN_SUCCESS", status="SUCCESS", ip_address=ip_addr, details=f"User logged in as {user['role']}")
            flash(f"Welcome back, {user['username']}!", "info")
            return redirect(url_for("index"))

        # Track failed login attempt
        tracker["count"] += 1
        if tracker["count"] >= 5:
            tracker["lockout_until"] = now + 300  # 5-minute lockout
            flash("Account temporarily locked due to 5 failed login attempts. Please try again in 5 minutes.", "error")
        else:
            flash("Invalid username or password.", "error")

        FAILED_LOGINS[username] = tracker
        db_manager.log_audit_event(user["id"] if user else None, username, "LOGIN_FAILED", status="FAILED", ip_address=ip_addr, details=f"Failed attempt {tracker['count']}/5")

    return render_template("login.html")

@app.route("/logout")
def logout():
    user_id = session.get("user_id")
    username = session.get("username", "Anonymous")
    ip_addr = request.remote_addr or "127.0.0.1"

    if user_id:
        db_manager.log_audit_event(user_id, username, "LOGOUT", status="SUCCESS", ip_address=ip_addr, details="User logged out")

    session.clear()
    flash("You have been logged out securely.", "info")
    return redirect(url_for("login"))

# --- APPLICATION ROUTES ---
@app.route("/")
def index():
    ml_metrics = evidence_engine.ml_classifier.metrics
    return render_template("index.html", ml_metrics=ml_metrics)

@app.route("/scan", methods=["POST"])
def start_scan():
    raw_url = request.form.get("url", "").strip()
    user_id = session.get("user_id")
    username = session.get("username", "Guest")
    ip_addr = request.remote_addr or "127.0.0.1"

    if not raw_url:
        flash("Please enter a valid website URL to analyze.", "error")
        return redirect(url_for("index"))

    # Resolve local demo shortcuts
    if raw_url == "/demo" or raw_url.endswith("/demo"):
        target_url = request.host_url.rstrip("/") + "/demo"
    elif not (raw_url.startswith("http://") or raw_url.startswith("https://") or raw_url.startswith("file://")):
        target_url = "https://" + raw_url
    else:
        target_url = raw_url

    try:
        db_manager.log_audit_event(user_id, username, "SCAN_STARTED", status="SUCCESS", ip_address=ip_addr, details=f"Target: {target_url}")

        # Step 1: Scan target URL and extract visible DOM elements + screenshot
        scan_result = scanner.scan_url(target_url, screenshots_dir=Config.SCREENSHOTS_DIR)

        if not scan_result.get("success"):
            error_msg = scan_result.get("error", "Failed to access target webpage.")
            db_manager.log_audit_event(user_id, username, "SCAN_FAILED", status="FAILED", ip_address=ip_addr, details=error_msg)
            flash(f"Scan failed for {target_url}: {error_msg}", "error")
            return redirect(url_for("index"))

        # Step 2: Analyze elements with Hybrid Detection & Evidence Engine
        elements = scan_result.get("elements", [])
        screenshot_path = scan_result.get("page_screenshot_path")
        detections = evidence_engine.analyze_elements(elements, target_url=target_url, page_screenshot_path=screenshot_path)

        # Step 3: Persist scan record & evidence in database
        scan_id = db_manager.save_scan(
            url=target_url,
            total_elements=scan_result.get("total_elements", 0),
            total_detections=len(detections),
            detections=detections
        )

        db_manager.log_audit_event(user_id, username, "SCAN_COMPLETED", status="SUCCESS", ip_address=ip_addr, details=f"Scan #{scan_id} completed with {len(detections)} findings")

        return redirect(url_for("view_results", scan_id=scan_id))

    except Exception as e:
        db_manager.log_audit_event(user_id, username, "SCAN_ERROR", status="ERROR", ip_address=ip_addr, details=str(e))
        flash(f"An unexpected error occurred during scanning: {str(e)}", "error")
        return redirect(url_for("index"))

@app.route("/results/<int:scan_id>")
def view_results(scan_id):
    user_id = session.get("user_id")
    username = session.get("username", "Guest")
    ip_addr = request.remote_addr or "127.0.0.1"

    scan_data = db_manager.get_scan(scan_id)
    if not scan_data:
        flash(f"Scan record #{scan_id} not found.", "error")
        return redirect(url_for("index"))
    
    db_manager.log_audit_event(user_id, username, "REPORT_VIEWED", status="SUCCESS", ip_address=ip_addr, details=f"Viewed Report #{scan_id}")

    # Compute Summary Statistics for Dashboard
    detections = scan_data.get("detections", [])
    high_count = sum(1 for d in detections if str(d.get("severity", "")).upper() == "HIGH")
    med_count = sum(1 for d in detections if str(d.get("severity", "")).upper() == "MEDIUM")
    low_count = sum(1 for d in detections if str(d.get("severity", "")).upper() == "LOW")
    
    cat_distribution = {}
    for d in detections:
        cat = d.get("pattern", "Other")
        cat_distribution[cat] = cat_distribution.get(cat, 0) + 1

    avg_confidence = 0.0
    if detections:
        conf_list = [float(d.get("confidence", 0)) for d in detections if d.get("confidence") is not None]
        if conf_list:
            avg_confidence = sum(conf_list) / len(conf_list)

    summary = {
        "high_count": high_count,
        "med_count": med_count,
        "low_count": low_count,
        "cat_distribution": cat_distribution,
        "avg_confidence": round(avg_confidence * 100, 1)
    }

    # Compute Deterministic Privacy Risk Score
    privacy_risk = evidence_engine.calculate_privacy_risk(detections)

    ml_metrics = evidence_engine.ml_classifier.metrics

    return render_template("results.html", scan=scan_data, summary=summary, privacy_risk=privacy_risk, ml_metrics=ml_metrics)

@app.route("/history")
def history():
    scans = db_manager.get_all_scans()
    return render_template("history.html", scans=scans)

@app.route("/demo")
def demo_page():
    return send_from_directory("demo_site", "index.html")

@app.route("/screenshots/<path:filename>")
def serve_screenshot(filename):
    return send_from_directory(Config.SCREENSHOTS_DIR, filename)

# --- ADMIN ROUTES ---
@app.route("/admin/audit-logs")
@admin_required
def admin_audit_logs():
    logs = db_manager.get_audit_logs(limit=100)
    return render_template("audit_logs.html", audit_logs=logs)

@app.route("/admin/users")
@admin_required
def admin_users():
    users = db_manager.get_all_users()
    return render_template("users.html", users=users)

@app.errorhandler(403)
def access_forbidden(e):
    return render_template("index.html", error="Access Denied: You do not have permission to view this resource."), 403

@app.errorhandler(404)
def page_not_found(e):
    return render_template("index.html", error="Requested page not found"), 404

@app.errorhandler(500)
def internal_server_error(e):
    return render_template("index.html", error="An internal server error occurred"), 500

if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=Config.DEBUG)
