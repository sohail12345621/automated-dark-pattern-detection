import unittest
from unittest.mock import patch, MagicMock
from detector.security_headers import (
    check_security_headers,
    check_tls_certificate,
    analyze_trackers,
    compute_domain_risk_score,
    analyze_security_posture
)

class TestSecurityHeadersModule(unittest.TestCase):
    """Unit tests for Phase 3: Security Headers, TLS verification, Tracker Inventory, and Domain Risk Score."""

    # 1. SECURITY HEADERS TESTS
    @patch("detector.security_headers.requests.head")
    def test_missing_security_headers_flagged(self, mock_head):
        mock_response = MagicMock()
        # Response missing all security headers
        mock_response.status_code = 200
        mock_response.headers = {"Content-Type": "text/html"}
        mock_head.return_value = mock_response

        findings, meta = check_security_headers("https://example.com")
        self.assertGreaterEqual(len(findings), 4)

        header_names = [f["element_text"] for f in findings]
        self.assertIn("Content-Security-Policy", header_names)
        self.assertIn("X-Frame-Options", header_names)
        self.assertIn("Strict-Transport-Security", header_names)

        # Validate evidence format
        sample = findings[0]
        self.assertEqual(sample["pattern"], "Missing Security Header")
        self.assertEqual(sample["source"], "Security Headers")
        self.assertIn("confidence", sample)
        self.assertIn("html_snippet", sample)

    @patch("detector.security_headers.requests.head")
    def test_all_security_headers_present(self, mock_head):
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.headers = {
            "Strict-Transport-Security": "max-age=31536000",
            "Content-Security-Policy": "default-src 'self'",
            "X-Frame-Options": "DENY",
            "X-Content-Type-Options": "nosniff",
            "Referrer-Policy": "strict-origin"
        }
        mock_head.return_value = mock_response

        findings, meta = check_security_headers("https://example.com")
        self.assertEqual(len(findings), 0)

    # 2. TLS & TRANSPORT ENCRYPTION TESTS
    def test_insecure_http_transport(self):
        findings, info = check_tls_certificate("http://example.com")
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["pattern"], "Insecure Transport")
        self.assertEqual(findings[0]["severity"], "HIGH")
        self.assertFalse(info["is_https"])

    @patch("detector.security_headers.socket.create_connection")
    @patch("detector.security_headers.ssl.create_default_context")
    def test_expired_tls_certificate(self, mock_ssl, mock_socket):
        mock_context = MagicMock()
        mock_ssock = MagicMock()
        # Certificate expired in 2020
        mock_ssock.getpeercert.return_value = {
            "notAfter": "Jan 01 00:00:00 2020 GMT"
        }
        mock_context.wrap_socket.return_value.__enter__.return_value = mock_ssock
        mock_ssl.return_value = mock_context

        findings, info = check_tls_certificate("https://example.com")
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["pattern"], "Invalid / Expired Certificate")
        self.assertEqual(findings[0]["severity"], "HIGH")
        self.assertFalse(info["valid"])

    # 3. TRACKER & THIRD-PARTY INVENTORY TESTS
    def test_known_tracker_detection(self):
        elements = [
            {
                "tag_name": "script",
                "attributes": {"src": "https://googletagmanager.com/gtm.js?id=GTM-1234"},
                "html_snippet": "<script src='https://googletagmanager.com/gtm.js'></script>"
            },
            {
                "tag_name": "script",
                "attributes": {"src": "https://connect.facebook.net/en_US/fbevents.js"},
                "html_snippet": "<script src='https://connect.facebook.net/en_US/fbevents.js'></script>"
            },
            {
                "tag_name": "script",
                "attributes": {"src": "/static/js/app.js"},
                "html_snippet": "<script src='/static/js/app.js'></script>"
            }
        ]

        findings, summary = analyze_trackers(elements, page_url="https://myshop.example.com")
        self.assertEqual(len(findings), 2)
        self.assertEqual(summary["total_trackers"], 2)
        self.assertIn("googletagmanager.com", summary["tracker_domains"])
        self.assertIn("connect.facebook.net", summary["tracker_domains"])

        # Check evidence format
        for f in findings:
            self.assertEqual(f["pattern"], "Third-Party Tracker Detected")
            self.assertEqual(f["source"], "Tracker Inventory")
            self.assertEqual(f["severity"], "HIGH")

    # 4. COMPOSITE DOMAIN RISK SCORE TESTS
    def test_composite_risk_score_calculation(self):
        detections = [
            {"pattern": "Urgency", "severity": "HIGH"},
            {"pattern": "Scarcity", "severity": "MEDIUM"}
        ]
        header_findings = [
            {"pattern": "Missing Security Header", "element_text": "Content-Security-Policy"},
            {"pattern": "Missing Security Header", "element_text": "Strict-Transport-Security"}
        ]
        tls_findings = [
            {"pattern": "Insecure Transport", "severity": "HIGH"}
        ]
        tracker_summary = {
            "total_trackers": 2,
            "total_third_party": 3
        }

        risk = compute_domain_risk_score(
            detections=detections,
            header_findings=header_findings,
            tls_findings=tls_findings,
            tracker_summary=tracker_summary
        )

        self.assertIn("score", risk)
        self.assertIn("level", risk)
        self.assertIn("breakdown", risk)
        self.assertGreaterEqual(risk["score"], 0)
        self.assertLessEqual(risk["score"], 100)

        # Verify component contributions exist
        breakdown = risk["breakdown"]
        self.assertGreater(breakdown["dark_patterns"], 0)
        self.assertGreater(breakdown["security_headers"], 0)
        self.assertGreater(breakdown["transport_tls"], 0)
        self.assertGreater(breakdown["trackers"], 0)

    # 5. URL VALIDATION ENFORCEMENT
    def test_outbound_ssrf_protection_in_headers_scan(self):
        # Attempting scanning internal IP should be blocked
        findings, meta = check_security_headers("http://169.254.169.254/latest/meta-data")
        self.assertEqual(len(findings), 0)
        self.assertIn("error", meta)

if __name__ == "__main__":
    unittest.main()
