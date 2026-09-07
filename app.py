from flask import Flask, render_template, request, redirect, url_for, flash, jsonify
from config.config import Config
import os

app = Flask(__name__)
app.config.from_object(Config)

# Ensure screenshots directory exists
os.makedirs(Config.SCREENSHOTS_DIR, exist_ok=True)

@app.route("/")
def index():
    return render_template("index.html")

@app.route("/scan", methods=["POST"])
def start_scan():
    url = request.form.get("url", "").strip()
    if not url:
        flash("Please enter a valid website URL.", "error")
        return redirect(url_for("index"))
    
    # Simple URL scheme fix if missing
    if not (url.startswith("http://") or url.startswith("https://") or url.startswith("file://")):
        url = "https://" + url
        
    # Placeholder response for Phase 1 (Scanning pipeline will be connected in subsequent phases)
    # Redirecting to results placeholder
    return redirect(url_for("view_results", scan_id=1))

@app.route("/results/<int:scan_id>")
def view_results(scan_id):
    # Placeholder scan data for Phase 1 foundation verification
    sample_scan = {
        "id": scan_id,
        "url": "http://127.0.0.1:5000/demo",
        "scan_date": "2026-09-07 22:25:00",
        "total_elements": 0,
        "total_detections": 0,
        "detections": []
    }
    return render_template("results.html", scan=sample_scan)

@app.route("/history")
def history():
    # Placeholder history data for Phase 1
    scans = []
    return render_template("history.html", scans=scans)

@app.errorhandler(404)
def page_not_found(e):
    return render_template("index.html", error="Page not found"), 404

@app.errorhandler(500)
def internal_server_error(e):
    return render_template("index.html", error="An internal server error occurred"), 500

if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=Config.DEBUG)
