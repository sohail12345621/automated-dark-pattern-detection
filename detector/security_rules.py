import re
import urllib.parse

class SecurityRuleEngine:
    """
    Deceptive-UI Security Rules Engine.
    Detects Insecure Forms, Hidden/Overlay Deception, Deceptive Links,
    Cookie/Consent Manipulation, and Excessive Permission Prompts.
    """

    def __init__(self):
        # Patterns for detecting domain names in anchor text
        self.domain_regex = re.compile(r"\b([a-zA-Z0-9-]+\.[a-zA-Z]{2,}(?::\d+)?)\b", re.IGNORECASE)

        # Cookie consent keywords
        self.cookie_accept_re = re.compile(r"\b(accept all|agree to all|allow all)\b", re.IGNORECASE)
        self.cookie_reject_re = re.compile(r"\b(reject all|decline all|reject non-essential|deny all)\b", re.IGNORECASE)

        # Permission prompt keywords/scripts
        self.perm_script_re = re.compile(r"(Notification\.requestPermission|navigator\.geolocation\.(?:getCurrentPosition|watchPosition))", re.IGNORECASE)

    def evaluate_element(self, element):
        """
        Evaluates an extracted DOM element dictionary against deceptive-UI security rules.
        Returns a structured detection dict if flagged, else None.
        """
        text = element.get("text", "")
        text_lower = text.lower()
        tag_name = element.get("tag_name", "").lower()
        elem_type = element.get("element_type", "").lower()
        attributes = element.get("attributes", {})
        style = attributes.get("style", "").lower()
        html_snippet = element.get("html_snippet", "")
        attr_text = f"{attributes.get('name', '')} {attributes.get('id', '')} {attributes.get('class', '')} {attributes.get('type', '')}".lower()

        # 1. Insecure Form Rule
        if tag_name == "form" or elem_type == "form":
            action = attributes.get("action", "").strip().lower()
            if action.startswith("http://"):
                return {
                    "pattern": "Insecure Form",
                    "confidence": 0.95,
                    "severity": "HIGH",
                    "source": "Rule",
                    "element_type": "form",
                    "element_text": text or "Insecure Form Submission",
                    "html_snippet": html_snippet,
                    "explanation": f"Form action transmits sensitive user data over unencrypted HTTP: '{action}'.",
                    "privacy_security_relevance": "Critical: Unencrypted form submissions are vulnerable to credential theft and Man-in-the-Middle (MitM) interception.",
                    "recommendation": "Migrate all form submission action endpoints to HTTPS with TLS encryption."
                }
        elif tag_name == "input" or elem_type == "input":
            input_type = attributes.get("type", "").lower()
            action = attributes.get("action", "").strip().lower()
            if input_type in ["password", "email", "creditcard"] and action.startswith("http://"):
                return {
                    "pattern": "Insecure Form",
                    "confidence": 0.95,
                    "severity": "HIGH",
                    "source": "Rule",
                    "element_type": "input",
                    "element_text": f"Sensitive input field ({input_type})",
                    "html_snippet": html_snippet,
                    "explanation": f"Sensitive {input_type} field submits data to an unencrypted HTTP endpoint '{action}'.",
                    "privacy_security_relevance": "Critical: Passwords and sensitive personal identifiers submitted over HTTP can be intercepted in plaintext.",
                    "recommendation": "Enforce HTTPS for all authentication and input collection forms."
                }

        # 2. Hidden/Overlay Deception (Clickjacking, invisible elements, zero opacity)
        is_iframe = tag_name == "iframe" or elem_type == "iframe"
        has_zero_opacity = "opacity:0" in style.replace(" ", "") or "opacity: 0.0" in style
        has_hidden_display = "visibility:hidden" in style.replace(" ", "") or "display:none" in style.replace(" ", "")
        has_offscreen_pos = "left:-999" in style.replace(" ", "") or "top:-999" in style.replace(" ", "")
        has_tiny_size = ("width:0" in style.replace(" ", "") or "height:0" in style.replace(" ", "") or
                         "width:1px" in style.replace(" ", "") or "height:1px" in style.replace(" ", ""))

        if is_iframe and (has_zero_opacity or has_hidden_display or has_tiny_size or has_offscreen_pos):
            return {
                "pattern": "Hidden/Overlay Deception",
                "confidence": 0.94,
                "severity": "HIGH",
                "source": "Rule",
                "element_type": "iframe",
                "element_text": attributes.get("src", "Hidden Iframe"),
                "html_snippet": html_snippet,
                "explanation": "Hidden or zero-opacity iframe detected on page, a hallmark of UI redressing or clickjacking deception.",
                "privacy_security_relevance": "High Security Risk: Transparent or hidden iframes can hijack user clicks to perform unauthorized actions.",
                "recommendation": "Remove invisible iframes or apply strict Content-Security-Policy frame-ancestors restrictions."
            }

        if (tag_name in ["a", "button", "div"] or elem_type in ["link", "button"]) and (has_zero_opacity or has_offscreen_pos):
            return {
                "pattern": "Hidden/Overlay Deception",
                "confidence": 0.91,
                "severity": "HIGH",
                "source": "Rule",
                "element_type": elem_type or tag_name,
                "element_text": text or "Hidden Clickable Element",
                "html_snippet": html_snippet,
                "explanation": "Clickable UI element uses transparent overlay styling or off-screen coordinates to deceive user interaction.",
                "privacy_security_relevance": "High Security Risk: Hidden clickable targets mislead users into executing unintended clicks or navigations.",
                "recommendation": "Ensure all interactive elements are fully visible, opaque, and positioned inside standard viewport boundaries."
            }

        # 3. Deceptive Links (Text shows one domain, href goes to another)
        if tag_name == "a" or elem_type == "link":
            href = attributes.get("href", "").strip()
            if href and text:
                domain_match = self.domain_regex.search(text)
                if domain_match:
                    visible_domain = domain_match.group(1).lower()
                    try:
                        parsed_href = urllib.parse.urlparse(href)
                        actual_domain = (parsed_href.hostname or "").lower()
                        # If href has a valid HTTP/HTTPS domain and it differs from displayed anchor domain
                        if actual_domain and visible_domain and not (actual_domain.endswith(visible_domain) or visible_domain.endswith(actual_domain)):
                            return {
                                "pattern": "Deceptive Links",
                                "confidence": 0.95,
                                "severity": "HIGH",
                                "source": "Rule",
                                "element_type": "link",
                                "element_text": text,
                                "html_snippet": html_snippet,
                                "explanation": f"Deceptive Link: Visible anchor text displays domain '{visible_domain}' but points to a different destination '{actual_domain}'.",
                                "privacy_security_relevance": "Critical Security Risk: Mismatched anchor text is a common phishing deception tactic designed to mislead users into visiting malicious targets.",
                                "recommendation": "Ensure link anchor text matches the actual target domain or clearly indicates navigation target."
                            }
                    except Exception:
                        pass

                # Homograph / Punycode check in href domain
                if "xn--" in href.lower():
                    return {
                        "pattern": "Deceptive Links",
                        "confidence": 0.90,
                        "severity": "HIGH",
                        "source": "Rule",
                        "element_type": "link",
                        "element_text": text or href,
                        "html_snippet": html_snippet,
                        "explanation": f"Punycode/homograph domain pattern detected in link href target: '{href}'.",
                        "privacy_security_relevance": "High Security Risk: Internationalized Domain Name (IDN) homograph attacks spoof trusted domain names using visually identical unicode characters.",
                        "recommendation": "Inspect and replace ambiguous punycode URL references with verified destination hosts."
                    }

        # 4. Cookie/Consent Manipulation (Asymmetrical choice, obscured reject)
        if "cookie" in attr_text or "consent" in attr_text or "cookie" in text_lower:
            if self.cookie_accept_re.search(text_lower):
                # Check if this container or element obscures reject
                if "reject" not in text_lower and ("tiny" in style or "font-size:0.7" in style.replace(" ", "") or "color:#" in style):
                    return {
                        "pattern": "Cookie/Consent Manipulation",
                        "confidence": 0.92,
                        "severity": "HIGH",
                        "source": "Rule",
                        "element_type": elem_type or "cookie_control",
                        "element_text": text,
                        "html_snippet": html_snippet,
                        "explanation": "Cookie consent interface promotes 'Accept All' while providing no balanced 'Reject All' alternative of equal prominence.",
                        "privacy_security_relevance": "High Privacy Risk: Asymmetrical consent banners coerce users into accepting non-essential tracking cookies and marketing profiling.",
                        "recommendation": "Provide equal visual prominence and accessibility for both 'Accept All' and 'Reject All' cookie choices."
                    }

        # 5. Excessive Permission Prompts (Notification or Geolocation on page load)
        onclick = attributes.get("onclick", "")
        script_content = text if tag_name == "script" or elem_type == "script" else onclick
        if self.perm_script_re.search(script_content) or self.perm_script_re.search(html_snippet):
            match = self.perm_script_re.search(script_content) or self.perm_script_re.search(html_snippet)
            method_name = match.group(1) if match else "Permission API"
            return {
                "pattern": "Excessive Permission Prompts",
                "confidence": 0.89,
                "severity": "MEDIUM",
                "source": "Rule",
                "element_type": elem_type or "script",
                "element_text": text or method_name,
                "html_snippet": html_snippet,
                "explanation": f"Automated script invokes browser permission request ('{method_name}') on page load without prior user interaction.",
                "privacy_security_relevance": "Medium Privacy Risk: Automatic permission prompting leads to permission fatigue and intrusive telemetry.",
                "recommendation": "Only trigger browser notification or location requests after explicit, user-initiated action."
            }

        return None
