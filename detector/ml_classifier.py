import os
import json
import joblib
from config.config import Config

class MLClassifier:
    """Machine Learning classifier using TF-IDF + Logistic Regression / LinearSVC."""

    def __init__(self, confidence_threshold=0.35):
        self.confidence_threshold = confidence_threshold
        self.model = None
        self.vectorizer = None
        self.metrics = {}
        self.is_loaded = False
        self.load_model()

    def load_model(self):
        """Loads trained model, vectorizer, and metrics metadata from disk."""
        model_path = os.path.join(Config.MODEL_DIR, "model.pkl")
        vectorizer_path = os.path.join(Config.MODEL_DIR, "vectorizer.pkl")
        metrics_path = os.path.join(Config.MODEL_DIR, "metrics.json")

        if os.path.exists(model_path) and os.path.exists(vectorizer_path):
            try:
                self.model = joblib.load(model_path)
                self.vectorizer = joblib.load(vectorizer_path)
                self.is_loaded = True
                
                if os.path.exists(metrics_path):
                    with open(metrics_path, "r", encoding="utf-8") as f:
                        self.metrics = json.load(f)
            except Exception as e:
                print(f"[MLClassifier Warning] Failed to load model: {e}")
        else:
            print("[MLClassifier Warning] Model files not found. Train model first using ml/train_model.py.")

    def evaluate_element(self, element):
        """
        Classifies a single DOM element text.
        Returns a detection dict if flagged with high confidence, else None.
        """
        if not self.is_loaded or not element.get("text"):
            return None

        text = element["text"].strip()
        if len(text) < 4:  # Skip trivial text strings
            return None

        try:
            X_vec = self.vectorizer.transform([text])
            
            # Support both predict_proba (LogisticRegression) and decision_function (LinearSVC)
            if hasattr(self.model, "predict_proba"):
                probs = self.model.predict_proba(X_vec)[0]
                max_idx = probs.argmax()
                predicted_label = self.model.classes_[max_idx]
                confidence = float(probs[max_idx])
            else:
                decision = self.model.decision_function(X_vec)[0]
                predicted_label = self.model.classes_[decision.argmax()]
                confidence = 0.85  # Default confidence for margin classifier

            if predicted_label != "normal" and confidence >= self.confidence_threshold:
                # Format category name nicely (e.g. "privacy_manipulation" -> "Privacy Manipulation")
                pattern_name = " ".join([w.capitalize() for w in predicted_label.split("_")])
                
                # Determine severity based on confidence level & category
                if confidence >= 0.75 or predicted_label in ["privacy_manipulation", "forced_action"]:
                    severity = "HIGH"
                elif confidence >= 0.55:
                    severity = "MEDIUM"
                else:
                    severity = "LOW"

                privacy_relevance = "Standard UI Deception Analysis"
                if predicted_label in ["privacy_manipulation", "preselection"]:
                    privacy_relevance = "High Risk: Deceptive consent UI compromises user data protection and privacy control."
                elif predicted_label in ["forced_action", "misdirection"]:
                    privacy_relevance = "Medium-High Risk: Manipulative choice UI steers users into unwanted tracking or data permissions."

                recommendations = {
                    "Privacy Manipulation": "Provide explicit, balanced opt-in/opt-out toggles for data collection.",
                    "Misdirection": "Use transparent, unambiguous button styling and label text.",
                    "Confirmshaming": "Use neutral decline options without guilt-inducing text.",
                    "Preselection": "Ensure optional tracking or marketing checkboxes are unchecked by default.",
                    "Forced Action": "Allow core functionality without requiring mandatory marketing consent.",
                    "Urgency": "Display legitimate, verifiable expiration timers.",
                    "Scarcity": "Ensure stock alerts reflect live inventory data."
                }

                return {
                    "pattern": pattern_name,
                    "confidence": round(confidence, 2),
                    "severity": severity,
                    "source": "ML",
                    "element_type": element.get("element_type", "text"),
                    "element_text": text,
                    "html_snippet": element.get("html_snippet", ""),
                    "explanation": f"Machine Learning model ('{self.metrics.get('model_name', 'TF-IDF Classifier')}') identified '{pattern_name}' with {round(confidence * 100)}% confidence.",
                    "privacy_security_relevance": privacy_relevance,
                    "recommendation": recommendations.get(pattern_name, "Review UI design for compliance with user choice standards.")
                }

        except Exception as e:
            print(f"[MLClassifier Error] Inference failed: {e}")

        return None

    def scan_elements(self, elements):
        """Scans a list of DOM elements using the ML classifier."""
        detections = []
        for elem in elements:
            det = self.evaluate_element(elem)
            if det:
                detections.append(det)
        return detections
