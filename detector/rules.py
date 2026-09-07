import re

class RuleEngine:
    """Rule-based dark pattern detector analyzing DOM elements and textual properties."""

    def __init__(self):
        # Keyword & Regex Rules for Dark Pattern Categories
        self.urgency_patterns = [
            r"\bhurry\b", r"\bact now\b", r"\blimited time\b", r"\bexpires\b",
            r"\bending soon\b", r"\bcountdown\b", r"\boffer ends\b",
            r"only \d+ minutes?", r"expires in \d+", r"\blast chance\b"
        ]

        self.scarcity_patterns = [
            r"only \d+ left", r"few remaining", r"limited stock",
            r"almost sold out", r"only \d+ available", r"\bstock is low\b",
            r"only \d+ items? left"
        ]

        self.confirmshaming_patterns = [
            r"no,?\s+i don'?t want", r"i don'?t want to save",
            r"no thanks,?\s+i prefer", r"i don'?t want the discount",
            r"no,?\s+thanks", r"prefer paying full price", r"nah,?\s+i'?ll pay full"
        ]

        self.forced_action_patterns = [
            r"must agree to receive promotional", r"mandatory subscription",
            r"required to continue", r"consent to marketing to proceed"
        ]

    def evaluate_element(self, element):
        """
        Evaluates a single extracted DOM element dictionary against rules.
        Returns a detection dict if flagged, or None.
        """
        text = element.get("text", "").lower()
        tag_name = element.get("tag_name", "")
        elem_type = element.get("element_type", "")
        is_checked = element.get("is_checked", False)
        attributes = element.get("attributes", {})

        # Rule 1: Preselection (Pre-checked optional input checkbox)
        if elem_type == "checkbox" or (tag_name == "input" and attributes.get("type") == "checkbox"):
            if is_checked:
                # Check if checkbox text or parent context implies newsletter or marketing
                return {
                    "pattern": "Preselection",
                    "confidence": 0.95,
                    "severity": "HIGH",
                    "source": "Rule",
                    "element_type": "checkbox",
                    "element_text": text or attributes.get("name", "Pre-checked Checkbox"),
                    "html_snippet": element.get("html_snippet", ""),
                    "explanation": "Optional checkbox is pre-selected by default, enrolling the user into terms or options without explicit opt-in."
                }

        # Rule 2: Urgency
        for pattern in self.urgency_patterns:
            if re.search(pattern, text):
                return {
                    "pattern": "Urgency",
                    "confidence": 0.90,
                    "severity": "HIGH",
                    "source": "Rule",
                    "element_type": elem_type,
                    "element_text": element.get("text", ""),
                    "html_snippet": element.get("html_snippet", ""),
                    "explanation": f"Element uses time-pressure language ('{pattern}') to rush user decisions."
                }

        # Rule 3: Scarcity
        for pattern in self.scarcity_patterns:
            if re.search(pattern, text):
                return {
                    "pattern": "Scarcity",
                    "confidence": 0.90,
                    "severity": "MEDIUM",
                    "source": "Rule",
                    "element_type": elem_type,
                    "element_text": element.get("text", ""),
                    "html_snippet": element.get("html_snippet", ""),
                    "explanation": f"Element triggers fear of missing out by claiming artificially limited availability ('{pattern}')."
                }

        # Rule 4: Confirmshaming
        for pattern in self.confirmshaming_patterns:
            if re.search(pattern, text):
                return {
                    "pattern": "Confirmshaming",
                    "confidence": 0.92,
                    "severity": "MEDIUM",
                    "source": "Rule",
                    "element_type": elem_type,
                    "element_text": element.get("text", ""),
                    "html_snippet": element.get("html_snippet", ""),
                    "explanation": "Element uses manipulative text designed to make the user feel guilty or foolish for opting out."
                }

        # Rule 5: Forced Action
        for pattern in self.forced_action_patterns:
            if re.search(pattern, text):
                return {
                    "pattern": "Forced Action",
                    "confidence": 0.88,
                    "severity": "HIGH",
                    "source": "Rule",
                    "element_type": elem_type,
                    "element_text": element.get("text", ""),
                    "html_snippet": element.get("html_snippet", ""),
                    "explanation": "Element requires the user to perform an unwanted secondary action to complete their primary task."
                }

        return None

    def scan_elements(self, elements):
        """Scans a list of DOM elements and returns all rule-based detections."""
        detections = []
        for elem in elements:
            detection = self.evaluate_element(elem)
            if detection:
                detections.append(detection)
        return detections
