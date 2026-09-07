import unittest
from database.db import DatabaseManager

class TestDatabaseManager(unittest.TestCase):
    def setUp(self):
        self.db = DatabaseManager()

    def test_save_and_get_scan(self):
        url = "http://127.0.0.1:5000/demo"
        total_elements = 10
        total_detections = 2
        detections = [
            {
                "pattern": "Urgency",
                "element_type": "text",
                "element_text": "Hurry! Offer expires in 05:00 minutes!",
                "confidence": 0.95,
                "severity": "HIGH",
                "source": "Hybrid",
                "explanation": "Test explanation",
                "html_snippet": "<div>Hurry</div>",
                "screenshot_path": "screenshots/test.png"
            },
            {
                "pattern": "Preselection",
                "element_type": "checkbox",
                "element_text": "newsletter",
                "confidence": 0.90,
                "severity": "HIGH",
                "source": "Rule",
                "explanation": "Test preselection",
                "html_snippet": "<input type='checkbox' checked>",
                "screenshot_path": "screenshots/test.png"
            }
        ]

        scan_id = self.db.save_scan(url, total_elements, total_detections, detections)
        self.assertIsNotNone(scan_id)
        self.assertGreater(scan_id, 0)

        scan_data = self.db.get_scan(scan_id)
        self.assertIsNotNone(scan_data)
        self.assertEqual(scan_data["url"], url)
        self.assertEqual(scan_data["total_elements"], total_elements)
        self.assertEqual(len(scan_data["detections"]), 2)

    def test_get_all_scans(self):
        scans = self.db.get_all_scans()
        self.assertIsInstance(scans, list)

if __name__ == "__main__":
    unittest.main()
