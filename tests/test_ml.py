import unittest
from detector.ml_classifier import MLClassifier

class TestMLClassifier(unittest.TestCase):
    def setUp(self):
        self.classifier = MLClassifier()

    def test_model_loaded(self):
        self.assertTrue(self.classifier.is_loaded, "ML model should be loaded from disk")

    def test_urgency_classification(self):
        elem = {"text": "Hurry! Offer expires in 05:00 minutes!", "element_type": "text"}
        res = self.classifier.evaluate_element(elem)
        self.assertIsNotNone(res)
        self.assertEqual(res["pattern"], "Urgency")
        self.assertEqual(res["source"], "ML")

    def test_scarcity_classification(self):
        elem = {"text": "Only 2 items left in stock!", "element_type": "text"}
        res = self.classifier.evaluate_element(elem)
        self.assertIsNotNone(res)
        self.assertEqual(res["pattern"], "Scarcity")

    def test_normal_text_classification(self):
        elem = {"text": "View Product & Add to Cart", "element_type": "button"}
        res = self.classifier.evaluate_element(elem)
        self.assertIsNone(res, "Normal UI text should not be flagged by ML classifier")

if __name__ == "__main__":
    unittest.main()
