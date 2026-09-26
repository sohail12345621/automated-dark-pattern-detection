import os
import sys
import json
import pandas as pd
import joblib
from sklearn.model_selection import train_test_split
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.svm import LinearSVC
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, confusion_matrix

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

    X = df["text"].astype(str)
    y = df["label"].astype(str)

    # Stratified Train/Test Split (80% train, 20% test)
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.20, stratify=y, random_state=42
    )

    print(f"Dataset split: {len(X_train)} training samples, {len(X_test)} testing samples")

    print("Fitting TF-IDF Vectorizer...")
    vectorizer = TfidfVectorizer(ngram_range=(1, 2), min_df=1, sublinear_tf=True, lowercase=True)
    X_train_vec = vectorizer.fit_transform(X_train)
    X_test_vec = vectorizer.transform(X_test)

    # Baseline Model: Logistic Regression
    print("Training Logistic Regression Model...")
    model_lr = LogisticRegression(C=5.0, max_iter=1000, random_state=42)
    model_lr.fit(X_train_vec, y_train)

    y_pred_lr = model_lr.predict(X_test_vec)
    acc_lr = accuracy_score(y_test, y_pred_lr)
    f1_lr = f1_score(y_test, y_pred_lr, average="macro")
    print(f"Logistic Regression -> Test Accuracy: {acc_lr * 100:.2f}%, Macro F1: {f1_lr:.4f}")

    selected_model = model_lr
    model_name = "Logistic Regression (TF-IDF)"
    y_pred = y_pred_lr

    # Compare with Linear SVM lightweight alternative if needed
    if acc_lr < 0.85:
        print("Testing LinearSVC alternative...")
        model_svm = LinearSVC(C=1.0, random_state=42, max_iter=2000)
        model_svm.fit(X_train_vec, y_train)
        y_pred_svm = model_svm.predict(X_test_vec)
        acc_svm = accuracy_score(y_test, y_pred_svm)
        f1_svm = f1_score(y_test, y_pred_svm, average="macro")
        print(f"LinearSVC -> Test Accuracy: {acc_svm * 100:.2f}%, Macro F1: {f1_svm:.4f}")

        if acc_svm > acc_lr:
            selected_model = model_svm
            model_name = "Linear SVM (TF-IDF)"
            y_pred = y_pred_svm

    # Final Evaluation Metrics on Held-Out Test Set
    test_accuracy = float(accuracy_score(y_test, y_pred))
    test_precision = float(precision_score(y_test, y_pred, average="macro"))
    test_recall = float(recall_score(y_test, y_pred, average="macro"))
    test_f1 = float(f1_score(y_test, y_pred, average="macro"))
    cm = confusion_matrix(y_test, y_pred).tolist()
    classes = sorted(list(y.unique()))

    metrics = {
        "model_name": model_name,
        "test_accuracy": round(test_accuracy, 4),
        "precision": round(test_precision, 4),
        "recall": round(test_recall, 4),
        "macro_f1": round(test_f1, 4),
        "total_samples": len(df),
        "train_samples": len(X_train),
        "test_samples": len(X_test),
        "classes": classes,
        "confusion_matrix": cm
    }

    print("\n--- FINAL TEST EVALUATION METRICS ---")
    print(f"Model: {model_name}")
    print(f"Test Accuracy: {metrics['test_accuracy'] * 100:.2f}%")
    print(f"Precision (macro): {metrics['precision']:.4f}")
    print(f"Recall (macro): {metrics['recall']:.4f}")
    print(f"Macro F1 Score: {metrics['macro_f1']:.4f}")

    model_path = os.path.join(model_dir, "model.pkl")
    vectorizer_path = os.path.join(model_dir, "vectorizer.pkl")
    metrics_path = os.path.join(model_dir, "metrics.json")

    joblib.dump(selected_model, model_path)
    joblib.dump(vectorizer, vectorizer_path)
    with open(metrics_path, "w", encoding="utf-8") as f:
        json.dump(metrics, f, indent=2)

    print(f"\nModel saved to: {model_path}")
    print(f"Vectorizer saved to: {vectorizer_path}")
    print(f"Metrics saved to: {metrics_path}")

    return metrics

if __name__ == "__main__":
    train_model()
