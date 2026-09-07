import os
from detector.rules import RuleEngine
from detector.ml_classifier import MLClassifier

class EvidenceEngine:
    """
    Hybrid Detection & Evidence Synthesis Engine.
    Combines rule-based heuristics and machine learning predictions into traceable evidence records.
    """

    def __init__(self):
        self.rule_engine = RuleEngine()
        self.ml_classifier = MLClassifier()

    def analyze_elements(self, elements, page_screenshot_path=None):
        """
        Analyzes a list of DOM element dictionaries.
        Fuses Rule-based and ML detections, formats explanations, and synthesizes evidence records.
        """
        raw_detections = []

        for elem in elements:
            rule_det = self.rule_engine.evaluate_element(elem)
            ml_det = self.ml_classifier.evaluate_element(elem)

            if rule_det and ml_det:
                # Hybrid Match Fusion
                hybrid_det = {
                    "pattern": rule_det["pattern"],
                    "confidence": min(1.0, round(max(rule_det["confidence"], ml_det["confidence"]) * 1.05, 2)),
                    "severity": rule_det["severity"],
                    "source": "Hybrid",
                    "element_type": elem.get("element_type", "UI Element"),
                    "element_text": elem.get("text", "") or rule_det.get("element_text", ""),
                    "html_snippet": elem.get("html_snippet", ""),
                    "explanation": f"Hybrid Detection: Rule engine matched category rules and ML classifier confirmed '{rule_det['pattern']}' pattern with {round(ml_det['confidence'] * 100)}% probability.",
                    "screenshot_path": page_screenshot_path
                }
                raw_detections.append(hybrid_det)
            elif rule_det:
                rule_det["screenshot_path"] = page_screenshot_path
                raw_detections.append(rule_det)
            elif ml_det:
                ml_det["screenshot_path"] = page_screenshot_path
                raw_detections.append(ml_det)

        # Deduplicate detections based on element text & pattern
        unique_detections = []
        seen_keys = set()

        for d in raw_detections:
            key = (d["pattern"], d["element_text"].strip(), d["html_snippet"].strip())
            if key not in seen_keys:
                seen_keys.add(key)
                unique_detections.append(d)

        return unique_detections
