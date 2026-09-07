import os
import sys
import pandas as pd
import joblib
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression

# Ensure root workspace directory is in sys.path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from config.config import Config

def train_model(dataset_path=None, model_dir=None):
    if dataset_path is None:
        dataset_path = os.path.join(Config.BASE_DIR, "ml", "dataset.csv")
    if model_dir is None:
        model_dir = Config.MODEL_DIR

    os.makedirs(model_dir, exist_ok=True)

    print(f"Loading dataset from: {dataset_path}")
    df = pd.read_csv(dataset_path)

    X = df["text"]
    y = df["label"]

    print("Fitting TF-IDF Vectorizer...")
    vectorizer = TfidfVectorizer(ngram_range=(1, 2), min_df=1, sublinear_tf=True, lowercase=True)
    X_vec = vectorizer.fit_transform(X)

    print("Training Logistic Regression Model...")
    model = LogisticRegression(C=10.0, max_iter=1000, random_state=42)
    model.fit(X_vec, y)

    train_acc = model.score(X_vec, y)
    print(f"Training Accuracy: {train_acc * 100:.2f}%")

    model_path = os.path.join(model_dir, "model.pkl")
    vectorizer_path = os.path.join(model_dir, "vectorizer.pkl")

    joblib.dump(model, model_path)
    joblib.dump(vectorizer, vectorizer_path)

    print(f"Model saved to: {model_path}")
    print(f"Vectorizer saved to: {vectorizer_path}")
    return True

if __name__ == "__main__":
    train_model()
