import os
import unittest
from app import app
from database.db import DatabaseManager

class TestFullIntegration(unittest.TestCase):
    def setUp(self):
        self.app = app
        self.client = self.app.test_client()
        self.db = DatabaseManager()

    def test_full_pipeline_with_demo_page(self):
        # 1. Resolve local demo site file path URL
        demo_path = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "demo_site", "index.html"))
        demo_url = "file:///" + demo_path.replace("\\", "/")

        # 2. Trigger scan via POST /scan
        response = self.client.post("/scan", data={"url": demo_url}, follow_redirects=True)
        self.assertEqual(response.status_code, 200)

        # 3. Verify scan record was saved in database
        scans = self.db.get_all_scans()
        self.assertGreater(len(scans), 0, "Scan archive should contain at least one scan")
        latest_scan = scans[0]
        
        # 4. Fetch detailed scan report with detections
        scan_detail = self.db.get_scan(latest_scan["id"])
        self.assertIsNotNone(scan_detail)
        self.assertGreater(scan_detail["total_elements"], 0, "DOM elements should be extracted")
        self.assertGreater(scan_detail["total_detections"], 0, "Dark patterns should be flagged")

        # 5. Verify detection content contains evidence
        patterns_flagged = [d["pattern"] for d in scan_detail["detections"]]
        self.assertTrue(any(p in patterns_flagged for p in ["Urgency", "Scarcity", "Confirmshaming", "Preselection"]))

        # 6. Verify history route renders scan report link
        history_resp = self.client.get("/history")
        self.assertEqual(history_resp.status_code, 200)
        self.assertIn("View Report", history_resp.get_data(as_text=True))

if __name__ == "__main__":
    unittest.main()
