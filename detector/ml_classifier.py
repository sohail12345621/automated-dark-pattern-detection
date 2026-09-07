import os
import joblib
from config.config import Config

class MLClassifier:
    """Machine Learning classifier using TF-IDF + Logistic Regression."""

    def __init__(self, confidence_threshold=0.35):
        self.confidence_threshold = confidence_threshold
        self.model = None
        self.vectorizer = None
        self.is_loaded = False
        self.load_model()

    def load_model(self):
        """Loads trained model and vectorizer from disk."""
        model_path = os.path.join(Config.MODEL_DIR, "model.pkl")
        vectorizer_path = os.path.join(Config.MODEL_DIR, "vectorizer.pkl")

        if os.path.exists(model_path) and os.path.exists(vectorizer_path):
            try:
                self.model = joblib.load(model_path)
                self.vectorizer = joblib.load(vectorizer_path)
                self.is_loaded = True
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
            probs = self.model.predict_proba(X_vec)[0]
            max_idx = probs.argmax()
            predicted_label = self.model.classes_[max_idx]
            confidence = float(probs[max_idx])

            if predicted_label != "normal" and confidence >= self.confidence_threshold:
                pattern_name = predicted_label.capitalize()
                
                # Determine severity based on confidence level
                if confidence >= 0.80:
                    severity = "HIGH"
                elif confidence >= 0.65:
                    severity = "MEDIUM"
                else:
                    severity = "LOW"

                return {
                    "pattern": pattern_name,
                    "confidence": round(confidence, 2),
                    "severity": severity,
                    "source": "ML",
                    "element_type": element.get("element_type", "text"),
                    "element_text": text,
                    "html_snippet": element.get("html_snippet", ""),
                    "explanation": f"Machine Learning classifier identified text pattern '{pattern_name}' with {round(confidence * 100)}% probability."
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
