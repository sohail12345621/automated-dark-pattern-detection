import unittest
from detector.evidence import EvidenceEngine

class TestEvidenceEngine(unittest.TestCase):
    def setUp(self):
        self.engine = EvidenceEngine()

    def test_hybrid_detection_and_fields(self):
        elem = {
            "text": "Hurry! Special 50% Offer expires in 05:00 minutes!",
            "element_type": "text_element",
            "tag_name": "div",
            "html_snippet": "<div class='urgency-banner'>Hurry! Special 50% Offer expires in 05:00 minutes!</div>"
        }
        detections = self.engine.analyze_elements([elem], target_url="http://test.local", page_screenshot_path="screenshots/test.png")
        self.assertEqual(len(detections), 1)
        det = detections[0]
        self.assertIn("finding_id", det)
        self.assertTrue(det["finding_id"].startswith("FIND-"))
        self.assertIn(det["source"], ["Hybrid", "Rule", "ML"])
        self.assertIsNotNone(det["explanation"])
        self.assertIsNotNone(det["privacy_security_relevance"])
        self.assertIsNotNone(det["recommendation"])
        self.assertEqual(det["screenshot_path"], "screenshots/test.png")

    def test_deduplication(self):
        elem1 = {"text": "Only 2 items left!", "element_type": "text", "tag_name": "span", "html_snippet": "<span>Only 2 items left!</span>"}
        elem2 = {"text": "Only 2 items left!", "element_type": "text", "tag_name": "span", "html_snippet": "<span>Only 2 items left!</span>"}
        detections = self.engine.analyze_elements([elem1, elem2])
        self.assertEqual(len(detections), 1, "Duplicate DOM detections should be deduplicated")

if __name__ == "__main__":
    unittest.main()
