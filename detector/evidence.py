import uuid
from datetime import datetime
from detector.rules import RuleEngine
from detector.ml_classifier import MLClassifier

class EvidenceEngine:
    """
    Hybrid Detection & Evidence Synthesis Engine with Privacy/Consent Cybersecurity Analysis.
    Combines rule-based heuristics and machine learning predictions into traceable evidence records.
    """

    def __init__(self):
        self.rule_engine = RuleEngine()
        self.ml_classifier = MLClassifier()

    def analyze_elements(self, elements, target_url="N/A", page_screenshot_path=None):
        """
        Analyzes a list of DOM element dictionaries.
        Fuses Rule-based and ML detections, formats explanations, and synthesizes evidence records.
        """
        raw_detections = []
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        for idx, elem in enumerate(elements):
            rule_det = self.rule_engine.evaluate_element(elem)
            ml_det = self.ml_classifier.evaluate_element(elem)

            finding_id = f"FIND-{uuid.uuid4().hex[:6].upper()}"

            if rule_det and ml_det:
                # Hybrid Match Fusion
                hybrid_det = {
                    "finding_id": finding_id,
                    "pattern": rule_det["pattern"],
                    "confidence": min(1.0, round(max(rule_det["confidence"], ml_det["confidence"]) * 1.05, 2)),
                    "severity": rule_det["severity"],
                    "source": "Hybrid",
                    "url": target_url,
                    "timestamp": timestamp,
                    "element_type": elem.get("element_type", "UI Element"),
                    "element_text": elem.get("text", "") or rule_det.get("element_text", ""),
                    "html_snippet": elem.get("html_snippet", ""),
                    "explanation": f"Hybrid Detection: Rule engine matched heuristic patterns and ML classifier confirmed '{rule_det['pattern']}' with {round(ml_det['confidence'] * 100)}% confidence.",
                    "privacy_security_relevance": rule_det.get("privacy_security_relevance", ml_det.get("privacy_security_relevance", "Privacy and consent UI manipulation detected.")),
                    "recommendation": rule_det.get("recommendation", ml_det.get("recommendation", "Review element design for user choice compliance.")),
                    "screenshot_path": page_screenshot_path
                }
                raw_detections.append(hybrid_det)
            elif rule_det:
                rule_det["finding_id"] = finding_id
                rule_det["url"] = target_url
                rule_det["timestamp"] = timestamp
                rule_det["screenshot_path"] = page_screenshot_path
                raw_detections.append(rule_det)
            elif ml_det:
                ml_det["finding_id"] = finding_id
                ml_det["url"] = target_url
                ml_det["timestamp"] = timestamp
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
