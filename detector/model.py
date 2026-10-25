"""Train, evaluate, save and load the phishing URL classifier."""
import csv
import json
from dataclasses import dataclass
from pathlib import Path

import joblib
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, confusion_matrix, f1_score, precision_score, recall_score
from sklearn.model_selection import train_test_split

from detector.features import FEATURE_NAMES, explain, extract_features

DEFAULT_MODEL_PATH = Path("models/url_model.joblib")


def load_dataset(csv_path: str | Path) -> tuple[list[str], list[int]]:
    """Read a CSV with columns `url` and `label` (1 = phishing, 0 = legitimate)."""
    urls, labels = [], []
    with open(csv_path, newline="", encoding="utf-8") as fh:
        for row in csv.DictReader(fh):
            urls.append(row["url"])
            labels.append(int(row["label"]))
    return urls, labels


def build_model(random_state: int = 42) -> RandomForestClassifier:
    return RandomForestClassifier(
        n_estimators=200, max_depth=12, class_weight="balanced", random_state=random_state, n_jobs=-1
    )


def train(csv_path: str | Path, model_path: str | Path = DEFAULT_MODEL_PATH, test_size: float = 0.2) -> dict:
    """Train on a CSV dataset, evaluate on a held-out split, save the model, return metrics."""
    urls, labels = load_dataset(csv_path)
    X = np.array([extract_features(u) for u in urls])
    y = np.array(labels)
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=test_size, stratify=y, random_state=42)

    model = build_model()
    model.fit(X_train, y_train)
    pred = model.predict(X_test)

    metrics = {
        "samples": len(y),
        "accuracy": round(float(accuracy_score(y_test, pred)), 4),
        "precision": round(float(precision_score(y_test, pred)), 4),
        "recall": round(float(recall_score(y_test, pred)), 4),
        "f1": round(float(f1_score(y_test, pred)), 4),
        "confusion_matrix": confusion_matrix(y_test, pred).tolist(),
        "top_features": sorted(
            zip(FEATURE_NAMES, map(float, model.feature_importances_)), key=lambda x: -x[1]
        )[:5],
    }
    Path(model_path).parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(model, model_path)
    Path(model_path).with_suffix(".metrics.json").write_text(json.dumps(metrics, indent=2))
    return metrics


@dataclass
class URLVerdict:
    url: str
    phishing_probability: float
    verdict: str
    reasons: list[str]


class URLDetector:
    def __init__(self, model_path: str | Path = DEFAULT_MODEL_PATH, threshold: float = 0.5):
        self.model = joblib.load(model_path)
        self.threshold = threshold

    def predict(self, url: str) -> URLVerdict:
        proba = float(self.model.predict_proba([extract_features(url)])[0][1])
        if proba >= max(self.threshold, 0.8):
            verdict = "phishing"
        elif proba >= self.threshold:
            verdict = "suspicious"
        else:
            verdict = "safe"
        return URLVerdict(url=url, phishing_probability=round(proba, 4), verdict=verdict, reasons=explain(url))
