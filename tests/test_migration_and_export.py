import json
import unittest
from app import app
from database.db import DatabaseManager

class TestMigrationAndExport(unittest.TestCase):
    """Unit tests for Phase 4: Safe DB migration, scan export (JSON & CSV), HTML escaping, and history filtering."""

    def setUp(self):
        self.app = app
        self.client = self.app.test_client()
        self.db = DatabaseManager()

    def test_safe_migration_twice_no_data_loss(self):
        """Verifies init_db migration runs repeatedly without error or data loss."""
        # 1. Seed scan with risk score & breakdown
        url = "https://migration-test.example.com"
        detections = [
            {
                "finding_id": "FIND-MIG001",
                "pattern": "Urgency",
                "element_type": "button",
                "element_text": "Only 2 Left!",
                "confidence": 0.95,
                "severity": "HIGH",
                "source": "Rule",
                "explanation": "Urgency trigger",
                "html_snippet": "<div>Only 2 Left!</div>",
                "screenshot_path": None
            }
        ]
        breakdown = {"dark_patterns": 15, "security_headers": 10, "transport_tls": 0, "trackers": 0}
        scan_id = self.db.save_scan(
            url=url,
            total_elements=5,
            total_detections=1,
            detections=detections,
            risk_score=25,
            risk_breakdown=breakdown
        )
        self.assertIsNotNone(scan_id)

        # 2. Run migration first time
        self.db.init_db()
        scan_after_1 = self.db.get_scan(scan_id)
        self.assertIsNotNone(scan_after_1)
        self.assertEqual(scan_after_1["url"], url)
        self.assertEqual(scan_after_1["risk_score"], 25)
        self.assertEqual(len(scan_after_1["detections"]), 1)

        # 3. Run migration second time (idempotency check)
        self.db.init_db()
        scan_after_2 = self.db.get_scan(scan_id)
        self.assertIsNotNone(scan_after_2)
        self.assertEqual(scan_after_2["url"], url)
        self.assertEqual(scan_after_2["risk_score"], 25)
        self.assertEqual(len(scan_after_2["detections"]), 1)
        self.assertEqual(scan_after_2["detections"][0]["finding_id"], "FIND-MIG001")

    def test_json_export_endpoint(self):
        """Verifies JSON export of scan report returns valid structure and metrics."""
        scan_id = self.db.save_scan(
            url="https://export-test.example.com",
            total_elements=8,
            total_detections=1,
            detections=[{
                "finding_id": "FIND-EXP001",
                "pattern": "Scarcity",
                "element_type": "p",
                "element_text": "Limited item",
                "confidence": 0.90,
                "severity": "MEDIUM",
                "source": "Hybrid",
                "explanation": "Scarcity indicator",
                "html_snippet": "<p>Limited</p>",
                "screenshot_path": None
            }],
            risk_score=35,
            risk_breakdown={"dark_patterns": 8, "security_headers": 15, "transport_tls": 0, "trackers": 12}
        )

        resp = self.client.get(f"/results/{scan_id}/export?format=json")
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.content_type, "application/json")

        data = json.loads(resp.data)
        self.assertEqual(data["scan_id"], scan_id)
        self.assertEqual(data["url"], "https://export-test.example.com")
        self.assertEqual(data["risk_score"], 35)
        self.assertIn("dark_patterns", data["risk_breakdown"])
        self.assertEqual(len(data["detections"]), 1)
        self.assertEqual(data["detections"][0]["finding_id"], "FIND-EXP001")

    def test_csv_export_endpoint(self):
        """Verifies CSV export of scan report returns correct text/csv format."""
        scan_id = self.db.save_scan(
            url="https://export-csv-test.example.com",
            total_elements=4,
            total_detections=1,
            detections=[{
                "finding_id": "FIND-CSV001",
                "pattern": "Confirmshaming",
                "element_type": "a",
                "element_text": "No thanks, I prefer paying full price",
                "confidence": 0.92,
                "severity": "HIGH",
                "source": "Rule",
                "explanation": "Guilt-inducing decline text",
                "html_snippet": "<a>No thanks</a>",
                "screenshot_path": None
            }]
        )

        resp = self.client.get(f"/results/{scan_id}/export?format=csv")
        self.assertEqual(resp.status_code, 200)
        self.assertIn("text/csv", resp.content_type)
        content = resp.data.decode("utf-8")
        self.assertIn("FIND-CSV001", content)
        self.assertIn("Confirmshaming", content)
        self.assertIn("finding_id,pattern,element_type,severity", content)

    def test_stored_html_snippet_escaping(self):
        """Verifies that stored HTML snippets containing executable scripts are safely escaped on render."""
        malicious_snippet = "<script>alert('xss-exploit')</script><img src='x' onerror='alert(1)'>"
        scan_id = self.db.save_scan(
            url="https://xss-test.example.com",
            total_elements=3,
            total_detections=1,
            detections=[{
                "finding_id": "FIND-XSS001",
                "pattern": "Hidden/Overlay Deception",
                "element_type": "script",
                "element_text": "XSS Probe",
                "confidence": 0.99,
                "severity": "HIGH",
                "source": "Rule",
                "explanation": "Testing HTML escaping",
                "html_snippet": malicious_snippet,
                "screenshot_path": None
            }]
        )

        resp = self.client.get(f"/results/{scan_id}")
        self.assertEqual(resp.status_code, 200)
        rendered_html = resp.data.decode("utf-8")

        # Must NOT contain raw unescaped script execution tag inside HTML snippet
        self.assertNotIn("<code>" + malicious_snippet + "</code>", rendered_html)
        # Must contain HTML-escaped entities
        self.assertIn("&lt;script&gt;alert(&#39;xss-exploit&#39;)&lt;/script&gt;", rendered_html)
        self.assertIn("&lt;img src=&#39;x&#39; onerror=&#39;alert(1)&#39;&gt;", rendered_html)

    def test_history_filtering_by_category_and_severity(self):
        """Verifies category and severity filters on the history view."""
        self.db.save_scan(
            url="https://history-filter-urgency.example.com",
            total_elements=5,
            total_detections=1,
            detections=[{
                "finding_id": "FIND-HIST001",
                "pattern": "Urgency",
                "element_type": "div",
                "element_text": "Flash Sale!",
                "confidence": 0.95,
                "severity": "HIGH",
                "source": "Rule",
                "explanation": "Urgency flag",
                "html_snippet": "<div>Sale</div>",
                "screenshot_path": None
            }]
        )

        # Filter by category
        resp_cat = self.client.get("/history?category=Urgency")
        self.assertEqual(resp_cat.status_code, 200)
        self.assertIn(b"history-filter-urgency.example.com", resp_cat.data)

        # Filter by severity
        resp_sev = self.client.get("/history?severity=HIGH")
        self.assertEqual(resp_sev.status_code, 200)
        self.assertIn(b"history-filter-urgency.example.com", resp_sev.data)

        # Filter by unmatched category
        resp_nomatch = self.client.get("/history?category=NonExistentCategoryXYZ")
        self.assertEqual(resp_nomatch.status_code, 200)
        self.assertNotIn(b"history-filter-urgency.example.com", resp_nomatch.data)

if __name__ == "__main__":
    unittest.main()
