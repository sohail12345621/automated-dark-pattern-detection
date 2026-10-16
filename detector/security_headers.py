import json
import os
import re
import socket
import ssl
import urllib.parse
from datetime import datetime, timezone
import requests

from config.config import Config
from security.url_validator import validate_url, is_local_demo_url

TRACKERS_FILE = os.path.join(os.path.dirname(__file__), "trackers.json")

SECURITY_HEADERS_DEF = {
    "Strict-Transport-Security": {
        "severity": "HIGH",
        "explanation": "Strict-Transport-Security (HSTS) header is missing, allowing potential SSL-stripping and downgrade attacks.",
        "privacy_security_relevance": "High Security Risk: Without HSTS, browsers may send unencrypted requests over HTTP.",
        "recommendation": "Configure Strict-Transport-Security: max-age=31536000; includeSubDomains; preload."
    },
    "Content-Security-Policy": {
        "severity": "HIGH",
        "explanation": "Content-Security-Policy (CSP) header is missing, leaving the application vulnerable to cross-site scripting (XSS) and data injection.",
        "privacy_security_relevance": "High Security Risk: Missing CSP allows execution of untrusted inline scripts and rogue tracking beacons.",
        "recommendation": "Implement a restrictive Content-Security-Policy restricting script-src, frame-ancestors, and connect-src."
    },
    "X-Frame-Options": {
        "severity": "MEDIUM",
        "explanation": "X-Frame-Options header is missing, exposing the webpage to clickjacking and UI redressing attacks.",
        "privacy_security_relevance": "Medium Security Risk: Third-party sites can embed this page inside an invisible iframe to hijack user clicks.",
        "recommendation": "Set X-Frame-Options: DENY or SAMEORIGIN, or configure frame-ancestors in CSP."
    },
    "X-Content-Type-Options": {
        "severity": "LOW",
        "explanation": "X-Content-Type-Options header is missing, allowing browsers to MIME-sniff response bodies into executable formats.",
        "privacy_security_relevance": "Low Security Risk: MIME sniffing can transform benign downloads into malicious executable scripts.",
        "recommendation": "Set X-Content-Type-Options: nosniff."
    },
    "Referrer-Policy": {
        "severity": "LOW",
        "explanation": "Referrer-Policy header is missing, which may leak sensitive URL parameters and browsing path to third parties.",
        "privacy_security_relevance": "Privacy Risk: Full URLs containing tokens or search queries may leak in the Referer header to external servers.",
        "recommendation": "Set Referrer-Policy: strict-origin-when-cross-origin or no-referrer."
    }
}


def load_known_trackers():
    """Loads list of known tracker domains from local trackers.json."""
    if os.path.exists(TRACKERS_FILE):
        try:
            with open(TRACKERS_FILE, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            pass
    return []


def check_security_headers(url, timeout=5):
    """
    Checks HTTP response security headers (HSTS, CSP, X-Frame-Options,
    X-Content-Type-Options, Referrer-Policy).
    All requests pass through the URL validator and use strict timeouts.
    """
    is_valid, err = validate_url(url, allow_local_demo=True)
    if not is_valid:
        return [], {"error": err, "headers": {}}

    findings = []
    headers_found = {}

    try:
        # First attempt lightweight HEAD request
        response = None
        try:
            response = requests.head(url, timeout=timeout, allow_redirects=True)
        except Exception:
            pass

        # Fallback to streaming GET if HEAD is rejected or unavailable
        if response is None or response.status_code in (405, 403, 501):
            response = requests.get(url, timeout=timeout, stream=True, allow_redirects=True)

        resp_headers = {k.lower(): v for k, v in response.headers.items()}
        headers_found = dict(response.headers)
        is_https = url.lower().startswith("https://")

        for header_name, defn in SECURITY_HEADERS_DEF.items():
            lower_name = header_name.lower()
            # HSTS is only applicable on HTTPS
            if lower_name == "strict-transport-security" and not is_https:
                continue

            if lower_name not in resp_headers:
                findings.append({
                    "pattern": "Missing Security Header",
                    "confidence": 1.0,
                    "severity": defn["severity"],
                    "source": "Security Headers",
                    "element_type": "header",
                    "element_text": header_name,
                    "html_snippet": f"<header {header_name}: missing>",
                    "explanation": defn["explanation"],
                    "privacy_security_relevance": defn["privacy_security_relevance"],
                    "recommendation": defn["recommendation"],
                    "screenshot_path": None
                })
    except Exception as e:
        # Graceful handling for unreachable sites or timeout
        return findings, {"error": str(e), "headers": {}}

    return findings, {"headers": headers_found}


def check_tls_certificate(url, timeout=5):
    """
    Analyzes transport encryption and TLS certificate validity/expiry
    using requests/ssl/socket standard libraries only.
    """
    is_valid, err = validate_url(url, allow_local_demo=True)
    if not is_valid:
        return [], {"error": err, "is_https": False, "valid": False}

    parsed = urllib.parse.urlparse(url)
    scheme = parsed.scheme.lower()
    findings = []
    tls_info = {"is_https": (scheme == "https"), "valid": False, "days_left": None}

    # 1. Plaintext HTTP transport check
    if scheme == "http":
        findings.append({
            "pattern": "Insecure Transport",
            "confidence": 1.0,
            "severity": "HIGH",
            "source": "TLS Check",
            "element_type": "protocol",
            "element_text": "HTTP (Unencrypted)",
            "html_snippet": "Scheme: http://",
            "explanation": f"Webpage operates over unencrypted HTTP: '{url}'. All communication is transmitted in plaintext.",
            "privacy_security_relevance": "Critical Security & Privacy Risk: Plaintext HTTP allows eavesdropping, credential theft, and traffic tampering.",
            "recommendation": "Enforce HTTPS transport with valid TLS encryption across all endpoints.",
            "screenshot_path": None
        })
        return findings, tls_info

    # 2. HTTPS TLS Certificate check
    if scheme == "https":
        hostname = parsed.hostname
        port = parsed.port or 443

        # Skip TLS socket handshake for local demo mock URLs
        if is_local_demo_url(url):
            tls_info["valid"] = True
            tls_info["days_left"] = 365
            return findings, tls_info

        try:
            context = ssl.create_default_context()
            with socket.create_connection((hostname, port), timeout=timeout) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()

            if cert and "notAfter" in cert:
                not_after_str = cert["notAfter"]
                # Format: 'May 15 12:00:00 2027 GMT'
                try:
                    expiry_date = datetime.strptime(not_after_str, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
                    days_left = (expiry_date - datetime.now(timezone.utc)).days
                    tls_info["valid"] = True
                    tls_info["days_left"] = days_left
                    tls_info["not_after"] = not_after_str

                    if days_left < 0:
                        tls_info["valid"] = False
                        findings.append({
                            "pattern": "Invalid / Expired Certificate",
                            "confidence": 1.0,
                            "severity": "HIGH",
                            "source": "TLS Check",
                            "element_type": "certificate",
                            "element_text": f"Expired ({abs(days_left)} days ago)",
                            "html_snippet": f"<cert notAfter='{not_after_str}'>",
                            "explanation": f"TLS certificate for {hostname} expired on {not_after_str}.",
                            "privacy_security_relevance": "Critical Security Risk: Expired certificates compromise encryption integrity and trigger browser warnings.",
                            "recommendation": "Renew and deploy a valid TLS certificate immediately.",
                            "screenshot_path": None
                        })
                    elif days_left < 14:
                        findings.append({
                            "pattern": "Certificate Expiring Soon",
                            "confidence": 0.9,
                            "severity": "MEDIUM",
                            "source": "TLS Check",
                            "element_type": "certificate",
                            "element_text": f"Expires in {days_left} days",
                            "html_snippet": f"<cert notAfter='{not_after_str}'>",
                            "explanation": f"TLS certificate for {hostname} expires in {days_left} days ({not_after_str}).",
                            "privacy_security_relevance": "Security Risk: Impending certificate expiration will cause service disruption and secure connection failures.",
                            "recommendation": "Renew the TLS certificate prior to expiration.",
                            "screenshot_path": None
                        })
                except Exception:
                    tls_info["valid"] = True
        except ssl.SSLError as e:
            tls_info["valid"] = False
            tls_info["error"] = str(e)
            findings.append({
                "pattern": "Invalid / Untrusted Certificate",
                "confidence": 1.0,
                "severity": "HIGH",
                "source": "TLS Check",
                "element_type": "certificate",
                "element_text": "SSL Verification Failed",
                "html_snippet": f"<cert error='{str(e)[:100]}'>",
                "explanation": f"TLS certificate validation failed for {hostname}: {str(e)}",
                "privacy_security_relevance": "Critical Security Risk: Invalid certificates allow Man-in-the-Middle attackers to intercept encrypted traffic.",
                "recommendation": "Install a valid certificate issued by a trusted Certificate Authority.",
                "screenshot_path": None
            })
        except Exception as e:
            tls_info["error"] = str(e)

    return findings, tls_info


def analyze_trackers(elements, page_url):
    """
    Builds third-party script and iframe domain inventory and flags known trackers
    matching detector/trackers.json.
    """
    known_trackers = load_known_trackers()
    page_host = (urllib.parse.urlparse(page_url).hostname or "").lower()

    third_party_domains = set()
    tracker_domains = set()
    findings = []
    seen_trackers = set()

    for elem in (elements or []):
        tag_name = (elem.get("tag_name") or elem.get("element_type") or "").lower()
        attributes = elem.get("attributes", {})
        src = attributes.get("src", "").strip()

        # Check script text for embedded tracker URLs if src is empty
        if not src and tag_name == "script":
            text = elem.get("text", "")
            matches = re.findall(r"https?://([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})", text)
            for domain in matches:
                domain_lower = domain.lower()
                if domain_lower != page_host and not page_host.endswith("." + domain_lower):
                    third_party_domains.add(domain_lower)
                    for tr in known_trackers:
                        if tr in domain_lower and domain_lower not in seen_trackers:
                            seen_trackers.add(domain_lower)
                            tracker_domains.add(domain_lower)
                            findings.append({
                                "pattern": "Third-Party Tracker Detected",
                                "confidence": 0.95,
                                "severity": "HIGH",
                                "source": "Tracker Inventory",
                                "element_type": "script",
                                "element_text": domain_lower,
                                "html_snippet": elem.get("html_snippet", f"<script ... {domain_lower} ...>"),
                                "explanation": f"Known third-party tracking/telemetry domain embedded in script: '{domain_lower}'.",
                                "privacy_security_relevance": "High Privacy Risk: Third-party trackers aggregate user data, fingerprint devices, and build behavioral profiles.",
                                "recommendation": "Block or gate tracking scripts behind explicit opt-in consent mechanisms.",
                                "screenshot_path": None
                            })
            continue

        if not src:
            continue

        # Handle protocol-relative URLs
        if src.startswith("//"):
            src = "https:" + src

        try:
            parsed_src = urllib.parse.urlparse(src)
            src_host = (parsed_src.hostname or "").lower()
            if not src_host:
                continue

            # First-party check
            if src_host == page_host or page_host.endswith("." + src_host) or src_host.endswith("." + page_host):
                continue

            third_party_domains.add(src_host)

            # Check known tracker match
            is_tracker = any(tr in src_host for tr in known_trackers)
            if is_tracker and src_host not in seen_trackers:
                seen_trackers.add(src_host)
                tracker_domains.add(src_host)
                findings.append({
                    "pattern": "Third-Party Tracker Detected",
                    "confidence": 0.95,
                    "severity": "HIGH",
                    "source": "Tracker Inventory",
                    "element_type": tag_name or "script",
                    "element_text": src_host,
                    "html_snippet": elem.get("html_snippet", f"<{tag_name} src='{src}'>"),
                    "explanation": f"Known third-party tracking/analytics service detected: '{src_host}'. Script monitors user behavior across sites.",
                    "privacy_security_relevance": "High Privacy Risk: Third-party trackers aggregate browsing profiles and harvest behavioral analytics.",
                    "recommendation": "Block or require explicit consent before loading third-party tracking scripts.",
                    "screenshot_path": None
                })
        except Exception:
            continue

    inventory_summary = {
        "page_domain": page_host,
        "third_party_domains": sorted(list(third_party_domains)),
        "tracker_domains": sorted(list(tracker_domains)),
        "total_third_party": len(third_party_domains),
        "total_trackers": len(tracker_domains)
    }

    return findings, inventory_summary


def compute_domain_risk_score(detections=None, header_findings=None, tls_findings=None, tracker_summary=None):
    """
    Computes a 0-100 per-domain composite risk score combining dark-pattern severity
    and security findings using weights configured in config/config.py.
    Returns composite score, risk level, and component breakdown.
    """
    weights = getattr(Config, "RISK_WEIGHTS", {
        "dark_pattern_high": 15,
        "dark_pattern_medium": 8,
        "dark_pattern_low": 3,
        "missing_security_header": 5,
        "insecure_transport_http": 20,
        "invalid_expired_cert": 25,
        "known_tracker_script": 10,
        "third_party_script": 2,
    })

    detections = detections or []
    header_findings = header_findings or []
    tls_findings = tls_findings or []
    tracker_summary = tracker_summary or {}

    # 1. Dark Pattern Findings Contribution
    dp_high = sum(1 for d in detections if str(d.get("severity", "")).upper() == "HIGH")
    dp_med = sum(1 for d in detections if str(d.get("severity", "")).upper() == "MEDIUM")
    dp_low = sum(1 for d in detections if str(d.get("severity", "")).upper() == "LOW")
    dp_score = (dp_high * weights.get("dark_pattern_high", 15) +
                dp_med * weights.get("dark_pattern_medium", 8) +
                dp_low * weights.get("dark_pattern_low", 3))

    # 2. Missing Security Headers Contribution
    headers_score = len(header_findings) * weights.get("missing_security_header", 5)

    # 3. Transport & TLS Contribution
    tls_score = 0
    for tf in tls_findings:
        pattern = tf.get("pattern", "")
        if pattern == "Insecure Transport":
            tls_score += weights.get("insecure_transport_http", 20)
        elif pattern in ("Invalid / Expired Certificate", "Invalid / Untrusted Certificate"):
            tls_score += weights.get("invalid_expired_cert", 25)
        elif pattern == "Certificate Expiring Soon":
            tls_score += int(weights.get("invalid_expired_cert", 25) * 0.4)

    # 4. Third-Party Tracker Contribution
    trackers_count = tracker_summary.get("total_trackers", 0)
    third_party_count = tracker_summary.get("total_third_party", 0)
    other_tp = max(0, third_party_count - trackers_count)
    trackers_score = (trackers_count * weights.get("known_tracker_script", 10) +
                      other_tp * weights.get("third_party_script", 2))

    raw_total = dp_score + headers_score + tls_score + trackers_score
    final_score = max(0, min(100, int(round(raw_total))))

    if final_score <= 25:
        level = "LOW"
    elif final_score <= 50:
        level = "MEDIUM"
    elif final_score <= 75:
        level = "HIGH"
    else:
        level = "CRITICAL"

    breakdown = {
        "dark_patterns": dp_score,
        "security_headers": headers_score,
        "transport_tls": tls_score,
        "trackers": trackers_score,
        "counts": {
            "dark_patterns_total": len(detections),
            "missing_headers_total": len(header_findings),
            "tls_issues_total": len(tls_findings),
            "trackers_total": trackers_count,
            "third_party_domains_total": third_party_count
        }
    }

    return {
        "score": final_score,
        "level": level,
        "breakdown": breakdown
    }


def analyze_security_posture(target_url, elements=None, page_screenshot_path=None, existing_detections=None):
    """
    Unified analyzer orchestrating security headers, TLS certificate verification,
    and third-party tracker inventory. Returns (evidence_findings, risk_summary).
    """
    existing_detections = existing_detections or []
    header_findings, _ = check_security_headers(target_url)
    tls_findings, _ = check_tls_certificate(target_url)
    tracker_findings, tracker_summary = analyze_trackers(elements or [], target_url)

    all_sec_findings = header_findings + tls_findings + tracker_findings
    for f in all_sec_findings:
        f["screenshot_path"] = page_screenshot_path

    risk_data = compute_domain_risk_score(
        detections=existing_detections,
        header_findings=header_findings,
        tls_findings=tls_findings,
        tracker_summary=tracker_summary
    )

    return all_sec_findings, risk_data
