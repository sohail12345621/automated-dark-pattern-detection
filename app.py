import os
from flask import Flask, render_template, request, redirect, url_for, flash, jsonify, send_from_directory
from config.config import Config
from crawler.selenium_scanner import SeleniumScanner
from detector.evidence import EvidenceEngine
from database.db import DatabaseManager

app = Flask(__name__)
app.config.from_object(Config)

# Ensure required runtime directories exist
os.makedirs(Config.SCREENSHOTS_DIR, exist_ok=True)

# Initialize persistent database manager and detector engines
db_manager = DatabaseManager()
evidence_engine = EvidenceEngine()
scanner = SeleniumScanner(headless=True, timeout=15)

@app.route("/")
def index():
    ml_metrics = evidence_engine.ml_classifier.metrics
    return render_template("index.html", ml_metrics=ml_metrics)

@app.route("/scan", methods=["POST"])
def start_scan():
    raw_url = request.form.get("url", "").strip()
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
        # Step 1: Scan target URL and extract visible DOM elements + screenshot
        scan_result = scanner.scan_url(target_url, screenshots_dir=Config.SCREENSHOTS_DIR)

        if not scan_result.get("success"):
            error_msg = scan_result.get("error", "Failed to access target webpage.")
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

        return redirect(url_for("view_results", scan_id=scan_id))

    except Exception as e:
        flash(f"An unexpected error occurred during scanning: {str(e)}", "error")
        return redirect(url_for("index"))

@app.route("/results/<int:scan_id>")
def view_results(scan_id):
    scan_data = db_manager.get_scan(scan_id)
    if not scan_data:
        flash(f"Scan record #{scan_id} not found.", "error")
        return redirect(url_for("index"))
    
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

    ml_metrics = evidence_engine.ml_classifier.metrics

    return render_template("results.html", scan=scan_data, summary=summary, ml_metrics=ml_metrics)

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

@app.errorhandler(404)
def page_not_found(e):
    return render_template("index.html", error="Requested page not found"), 404

@app.errorhandler(500)
def internal_server_error(e):
    return render_template("index.html", error="An internal server error occurred"), 500

if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=Config.DEBUG)
