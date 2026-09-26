import re

class RuleEngine:
    """Rule-based dark pattern detector analyzing DOM elements and textual properties."""

    def __init__(self):
        # 1. Urgency Patterns
        self.urgency_patterns = [
            r"\bhurry\b", r"\bact now\b", r"\blimited time\b", r"\bexpires\b",
            r"\bending soon\b", r"\bcountdown\b", r"\boffer ends\b",
            r"only \d+ minutes?", r"expires in \d+", r"\blast chance\b", r"\bflash sale\b"
        ]

        # 2. Scarcity Patterns
        self.scarcity_patterns = [
            r"only \d+ left", r"few remaining", r"limited stock",
            r"almost sold out", r"only \d+ available", r"\bstock is low\b",
            r"only \d+ items? left", r"\bhigh demand\b", r"\bviewing this offer\b"
        ]

        # 3. Confirmshaming Patterns
        self.confirmshaming_patterns = [
            r"no,?\s+i don'?t want", r"i don'?t want to save",
            r"no thanks,?\s+i prefer", r"i don'?t want the discount",
            r"no,?\s+thanks", r"prefer paying full price", r"nah,?\s+i'?ll pay full",
            r"hate saving money", r"don'?t care about privacy", r"prefer paying extra"
        ]

        # 4. Forced Action Patterns
        self.forced_action_patterns = [
            r"must agree to receive promotional", r"mandatory subscription",
            r"required to continue", r"consent to marketing to proceed",
            r"must create an account", r"mandatory registration", r"must allow push notifications"
        ]

        # 5. Misdirection Patterns (Visual & Logical Tricks)
        self.misdirection_patterns = [
            r"accept all.*continue", r"uncheck.*do not wish", r"uncheck.*if you do not",
            r"click.*cancel.*to proceed", r"download now.*adware", r"refrain from not",
            r"keep my discount.*subscribes", r"check if you do not want us to refrain"
        ]

        # 6. Privacy Manipulation Patterns (Deceptive Cookie/Consent Controls)
        self.privacy_patterns = [
            r"accept all cookies", r"allow all \d+\+ ad partners", r"sell your personal",
            r"share your browsing profile", r"personalized ads and profiling",
            r"by remaining on this site you consent", r"do not sell my personal info",
            r"disable non-essential data selling", r"allow tracking to keep service free"
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
        attr_text = f"{attributes.get('name', '')} {attributes.get('id', '')} {attributes.get('class', '')}".lower()

        # Rule 1: Preselection (Pre-checked optional input checkbox / toggle)
        if elem_type in ["checkbox", "radio"] or (tag_name == "input" and attributes.get("type") in ["checkbox", "radio"]):
            if is_checked:
                is_privacy = any(w in (text + " " + attr_text) for w in ["cookie", "tracking", "analytics", "marketing", "partner", "data", "privacy", "newsletter", "terms", "opt_in"])
                pattern = "Privacy Manipulation" if is_privacy else "Preselection"
                return {
                    "pattern": pattern,
                    "confidence": 0.95,
                    "severity": "HIGH",
                    "source": "Rule",
                    "element_type": "checkbox",
                    "element_text": element.get("text", "") or attributes.get("name", "Pre-checked Input"),
                    "html_snippet": element.get("html_snippet", ""),
                    "explanation": "Optional consent or tracking option is pre-selected by default without explicit opt-in.",
                    "privacy_security_relevance": "High Risk: Pre-selected privacy/consent options violate explicit consent requirements (GDPR/CCPA).",
                    "recommendation": "Uncheck optional checkboxes by default and require explicit user opt-in."
                }

        # Rule 2: Privacy Manipulation
        for pattern in self.privacy_patterns:
            if re.search(pattern, text) or re.search(pattern, attr_text):
                return {
                    "pattern": "Privacy Manipulation",
                    "confidence": 0.92,
                    "severity": "HIGH",
                    "source": "Rule",
                    "element_type": elem_type,
                    "element_text": element.get("text", ""),
                    "html_snippet": element.get("html_snippet", ""),
                    "explanation": f"Element uses deceptive cookie/consent phrasing ('{pattern}') to manipulate data privacy choices.",
                    "privacy_security_relevance": "Critical: Coerces users into surrendering personal data, cross-site tracking, and third-party data selling.",
                    "recommendation": "Provide clear, equal-weight 'Reject All' and 'Accept All' consent choices."
                }

        # Rule 3: Misdirection
        for pattern in self.misdirection_patterns:
            if re.search(pattern, text):
                return {
                    "pattern": "Misdirection",
                    "confidence": 0.90,
                    "severity": "HIGH",
                    "source": "Rule",
                    "element_type": elem_type,
                    "element_text": element.get("text", ""),
                    "html_snippet": element.get("html_snippet", ""),
                    "explanation": "Element employs misleading visual hierarchy or confusing double-negative phrasing to steer choices.",
                    "privacy_security_relevance": "Medium Risk: Confusing button choices lead users into unintended consent or financial decisions.",
                    "recommendation": "Use unambiguous action labels and balanced primary/secondary button styling."
                }

        # Rule 4: Confirmshaming
        for pattern in self.confirmshaming_patterns:
            if re.search(pattern, text):
                is_privacy = "privacy" in text or "security" in text
                return {
                    "pattern": "Confirmshaming",
                    "confidence": 0.92,
                    "severity": "MEDIUM" if not is_privacy else "HIGH",
                    "source": "Rule",
                    "element_type": elem_type,
                    "element_text": element.get("text", ""),
                    "html_snippet": element.get("html_snippet", ""),
                    "explanation": "Element uses emotionally manipulative text to induce guilt for declining or opting out.",
                    "privacy_security_relevance": "Medium Risk: Emotional coercion undermines free choice in privacy and purchase decisions.",
                    "recommendation": "Replace guilt-inducing copy with neutral decline text such as 'No thanks' or 'Close'."
                }

        # Rule 5: Urgency
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
                    "explanation": f"Element uses artificial time-pressure language ('{pattern}') to induce rushed decision making.",
                    "privacy_security_relevance": "Low Risk: Time pressure leads to impulse transactions and rushed consent agreement.",
                    "recommendation": "Ensure offer countdown timers reflect legitimate, verifiable expiration limits."
                }

        # Rule 6: Scarcity
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
                    "explanation": f"Element triggers fear of missing out by claiming artificially limited stock availability ('{pattern}').",
                    "privacy_security_relevance": "Low Risk: Manipulates user perception of supply availability.",
                    "recommendation": "Display real-time inventory counts only when backed by live database metrics."
                }

        # Rule 7: Forced Action
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
                    "explanation": "Element requires the user to perform an unwanted secondary action (e.g. newsletter/tracking) to proceed.",
                    "privacy_security_relevance": "High Risk: Forces unnecessary personal data disclosure as a gatekeeper to essential features.",
                    "recommendation": "Decouple primary user tasks from optional marketing or account registration requirements."
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
