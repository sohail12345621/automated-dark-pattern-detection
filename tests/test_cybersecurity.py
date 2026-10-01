import os
import unittest
from werkzeug.security import generate_password_hash, check_password_hash
from app import app, db_manager, FAILED_LOGINS
from detector.evidence import EvidenceEngine

class TestCybersecurityModule(unittest.TestCase):
    def setUp(self):
        self.app = app
        self.client = self.app.test_client()
        self.db = db_manager
        self.evidence_engine = EvidenceEngine()
        FAILED_LOGINS.clear()

    # 1. AUTHENTICATION & PASSWORD HASHING TESTS
    def test_password_hashing(self):
        password = "SecurePassword123"
        pwd_hash = generate_password_hash(password)
        self.assertNotEqual(password, pwd_hash)
        self.assertTrue(check_password_hash(pwd_hash, password))
        self.assertFalse(check_password_hash(pwd_hash, "WrongPassword"))

    def test_user_registration_and_login(self):
        username = "testuser_cyber"
        email = "testuser@cyber.local"
        password = "UserPassword123"

        # Register
        reg_resp = self.client.post("/register", data={
            "username": username,
            "email": email,
            "password": password,
            "confirm_password": password
        }, follow_redirects=True)
        self.assertEqual(reg_resp.status_code, 200)

        # Login Success
        login_resp = self.client.post("/login", data={
            "username": username,
            "password": password
        }, follow_redirects=True)
        self.assertEqual(login_resp.status_code, 200)
        self.assertIn(b"Welcome back", login_resp.data)

        # Logout
        logout_resp = self.client.get("/logout", follow_redirects=True)
        self.assertEqual(logout_resp.status_code, 200)
        self.assertIn(b"logged out", logout_resp.data)

    # 2. SESSION SECURITY CONFIGURATION
    def test_session_cookie_security(self):
        self.assertTrue(self.app.config.get("SESSION_COOKIE_HTTPONLY"), "HTTPOnly cookie flag must be True")
        self.assertEqual(self.app.config.get("SESSION_COOKIE_SAMESITE"), "Lax", "SameSite flag must be Lax")

    # 3. LOGIN PROTECTION & BRUTE-FORCE LOCKOUT
    def test_brute_force_login_lockout(self):
        username = "lockout_user"
        email = "lockout@cyber.local"
        password = "CorrectPassword123"

        self.client.post("/register", data={
            "username": username,
            "email": email,
            "password": password,
            "confirm_password": password
        })

        # 5 failed attempts
        for i in range(5):
            res = self.client.post("/login", data={"username": username, "password": "WrongPassword"})
            self.assertEqual(res.status_code, 200)

        # 6th attempt should trigger lockout message
        lockout_resp = self.client.post("/login", data={"username": username, "password": password})
        self.assertIn(b"locked", lockout_resp.data.lower())

    # 4. ROLE-BASED ACCESS CONTROL (RBAC) TESTS
    def test_rbac_user_restricted_from_admin_routes(self):
        username = "standard_user"
        email = "std@cyber.local"
        password = "UserPassword123"

        self.client.post("/register", data={"username": username, "email": email, "password": password, "confirm_password": password})
        self.client.post("/login", data={"username": username, "password": password})

        # User attempting admin audit log route
        admin_logs_resp = self.client.get("/admin/audit-logs")
        self.assertEqual(admin_logs_resp.status_code, 403)

        # User attempting admin users route
        admin_users_resp = self.client.get("/admin/users")
        self.assertEqual(admin_users_resp.status_code, 403)

    def test_rbac_admin_access_allowed(self):
        # Default seeded admin
        self.client.post("/login", data={"username": "admin", "password": "admin123"})

        logs_resp = self.client.get("/admin/audit-logs")
        self.assertEqual(logs_resp.status_code, 200)
        self.assertIn(b"Security Audit Log Console", logs_resp.data)

        users_resp = self.client.get("/admin/users")
        self.assertEqual(users_resp.status_code, 200)
        self.assertIn(b"Registered User Accounts", users_resp.data)

    # 5. SECURITY AUDIT LOGGING TESTS
    def test_audit_logging(self):
        logs_before = len(self.db.get_audit_logs())
        self.db.log_audit_event(None, "audit_test", "TEST_ACTION", status="SUCCESS", ip_address="127.0.0.1", details="Test details")
        logs_after = self.db.get_audit_logs()
        self.assertGreater(len(logs_after), logs_before)
        latest_log = logs_after[0]
        self.assertEqual(latest_log["action"], "TEST_ACTION")

    # 6. PRIVACY RISK SCORE CALCULATION TESTS
    def test_privacy_risk_score_calculation(self):
        detections = [
            {"pattern": "Privacy Manipulation", "severity": "HIGH"},
            {"pattern": "Preselection", "severity": "HIGH"},
            {"pattern": "Misdirection", "severity": "MEDIUM"}
        ]
        risk = self.evidence_engine.calculate_privacy_risk(detections)
        self.assertEqual(risk["level"], "HIGH")
        self.assertGreaterEqual(risk["score"], 45)
        self.assertGreater(len(risk["reasons"]), 0)

    # 7. REGRESSION TEST FOR SCANNER & DASHBOARD
    def test_regression_scanner_and_dashboard(self):
        index_resp = self.client.get("/")
        self.assertEqual(index_resp.status_code, 200)
        self.assertIn(b"Dark Pattern Identification", index_resp.data)

if __name__ == "__main__":
    unittest.main()
