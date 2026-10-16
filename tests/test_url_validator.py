import unittest
from security.url_validator import validate_url, is_local_demo_url
from app import app, is_scan_rate_limited, SCAN_RATE_LIMITS

class TestUrlValidatorAndSecurity(unittest.TestCase):
    def setUp(self):
        self.app = app
        self.client = self.app.test_client()
        SCAN_RATE_LIMITS.clear()

    def test_private_ip_blocked(self):
        for private_url in [
            "http://127.0.0.1:8080/admin",
            "http://10.0.0.1/status",
            "http://192.168.1.1/router",
            "http://172.16.0.1/server",
            "http://169.254.169.254/latest/meta-data/"
        ]:
            is_valid, err = validate_url(private_url, allow_local_demo=False)
            self.assertFalse(is_valid, f"Expected {private_url} to be blocked")
            self.assertIsNotNone(err)

    def test_bad_scheme_blocked(self):
        for bad_url in [
            "ftp://example.com/file.txt",
            "file:///etc/passwd",
            "javascript:alert(1)",
            "data:text/html,<h1>test</h1>"
        ]:
            is_valid, err = validate_url(bad_url, allow_local_demo=False)
            self.assertFalse(is_valid, f"Expected {bad_url} to be blocked")
            self.assertIn("scheme", err.lower())

    def test_valid_public_url_passes(self):
        is_valid, err = validate_url("https://example.com", allow_local_demo=False)
        self.assertTrue(is_valid)
        self.assertIsNone(err)

    def test_local_demo_allowlist(self):
        self.assertTrue(is_local_demo_url("http://127.0.0.1:5000/demo"))
        is_valid, err = validate_url("http://127.0.0.1:5000/demo", allow_local_demo=True)
        self.assertTrue(is_valid)

    def test_credentials_in_url_rejected(self):
        is_valid, err = validate_url("http://admin:secret@example.com", allow_local_demo=False)
        self.assertFalse(is_valid)
        self.assertIn("credentials", err.lower())

    def test_security_headers_present(self):
        resp = self.client.get("/")
        self.assertEqual(resp.headers.get("X-Content-Type-Options"), "nosniff")
        self.assertEqual(resp.headers.get("X-Frame-Options"), "DENY")
        self.assertIn("default-src 'self'", resp.headers.get("Content-Security-Policy", ""))

    def test_scan_rate_limiting(self):
        ip = "192.0.2.1"
        for _ in range(10):
            self.assertFalse(is_scan_rate_limited(ip, limit=10, window=60))
        # 11th scan should be rate limited
        self.assertTrue(is_scan_rate_limited(ip, limit=10, window=60))

if __name__ == "__main__":
    unittest.main()
