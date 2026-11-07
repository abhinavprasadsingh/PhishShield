from __future__ import annotations

import csv
import io
import ipaddress
import os
from pathlib import Path
from typing import Any

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

from src.features import FEATURE_NAMES, extract_features, normalize_url

app = FastAPI(title="PhishShield API", version="1.0.0")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["GET", "POST"],
    allow_headers=["Content-Type"],
)

ROOT = Path(__file__).resolve().parents[1]
MODEL_PATH = ROOT / "models" / "phishing_model.joblib"
_model: Any = None
_model_checked = False
SHORTENERS = {"bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly", "cutt.ly"}
SUSPICIOUS = {"login", "verify", "account", "update", "secure", "password", "banking", "signin", "confirm", "wallet", "recover"}


class AnalyzeRequest(BaseModel):
    url: str = Field(min_length=1, max_length=2048)


class CsvRequest(BaseModel):
    csv_text: str = Field(min_length=1, max_length=2_000_000)


def load_model():
    global _model, _model_checked
    if _model_checked:
        return _model
    _model_checked = True
    if MODEL_PATH.exists():
        try:
            import joblib
            _model = joblib.load(MODEL_PATH)
        except Exception:
            _model = None
    return _model


def assess(features: dict[str, int]) -> dict[str, Any]:
    reasons: list[str] = []
    if features["has_ip_host"]:
        reasons.append("The hostname is an IP address rather than a typical domain.")
    if features["has_url_shortener"]:
        reasons.append("The hostname belongs to a URL-shortening service, which can hide the final destination.")
    if features["has_suspicious_word"]:
        reasons.append("The URL contains a word often used in account or security lures.")
    if features["at_count"]:
        reasons.append("The URL contains an @ symbol, which can make the destination confusing.")
    if features["subdomain_count"] >= 3:
        reasons.append("The hostname has several subdomain levels. Check which domain actually owns the site.")
    if features["url_length"] >= 100:
        reasons.append("The URL is unusually long.")
    if features["hyphen_count"] >= 3:
        reasons.append("The URL contains multiple hyphens.")
    if not features["uses_https"]:
        reasons.append("The URL does not use HTTPS.")
    score = min(95, len(reasons) * 15)
    label = "Higher-risk signals" if score >= 45 else "Some caution advised" if score >= 15 else "Fewer obvious signals"
    if not reasons:
        reasons.append("No simple warning patterns were detected. This does not prove the site is safe.")

    model = load_model()
    prediction = None
    probability = None
    mode = "Heuristic demo mode"
    model_confidence = None
    feature_importance = []
    if model is not None:
        try:
            import pandas as pd
            row = pd.DataFrame([[features[name] for name in FEATURE_NAMES]], columns=FEATURE_NAMES)
            prediction = int(model.predict(row)[0])
            if hasattr(model, "predict_proba"):
                probabilities = model.predict_proba(row)[0]
                classes = list(model.classes_)
                if 1 in classes:
                    probability = round(float(probabilities[classes.index(1)]) * 100, 1)
                model_confidence = round(float(max(probabilities)) * 100, 1)
            estimator = model
            if hasattr(estimator, "named_steps"):
                estimator = estimator.named_steps.get("model", estimator)
            importance = getattr(estimator, "feature_importances_", None)
            if importance is None and hasattr(estimator, "coef_"):
                try:
                    importance = abs(estimator.coef_[0])
                except (IndexError, TypeError):
                    importance = None
            if importance is not None and len(importance) == len(FEATURE_NAMES):
                feature_importance = sorted(
                    [{"feature": name.replace("_", " ").title(), "importance": float(value)}
                     for name, value in zip(FEATURE_NAMES, importance)],
                    key=lambda item: item["importance"], reverse=True
                )[:8]
            mode = "Trained machine-learning model"
            label = "Potential phishing URL" if prediction == 1 else "Model found fewer phishing signals"
        except Exception:
            prediction = None
            probability = None
            model_confidence = None
            feature_importance = []
            mode = "Heuristic demo mode (model unavailable)"

    return {
        "risk_label": label,
        "risk_score": score,
        "reasons": reasons,
        "prediction": prediction,
        "phishing_probability": probability,
        "model_confidence": model_confidence,
        "feature_importance": feature_importance,
        "mode": mode,
        "features": features,
    }


@app.get("/")
@app.get("/health")
def health():
    return {"status": "ok", "service": "PhishShield API", "model_available": load_model() is not None}


@app.post("/analyze")
def analyze(payload: AnalyzeRequest):
    try:
        normalized = normalize_url(payload.url)
        features = extract_features(normalized)
        result = assess(features)
        return {"url": normalized, **result}
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@app.post("/scan-csv")
def scan_csv(payload: CsvRequest):
    try:
        reader = csv.DictReader(io.StringIO(payload.csv_text))
        if not reader.fieldnames or "url" not in set(reader.fieldnames):
            raise HTTPException(status_code=400, detail="CSV must contain a column named url.")
        rows = []
        scanned = 0
        skipped = 0
        for row in reader:
            if scanned + skipped >= 1000:
                break
            raw_url = (row.get("url") or "").strip()
            if not raw_url:
                skipped += 1
                continue
            try:
                normalized = normalize_url(raw_url)
                features = extract_features(normalized)
                result = assess(features)
                rows.append({
                    "url": normalized,
                    "model_result": ("Potential phishing" if result["prediction"] == 1 else "Likely legitimate (model class)") if result["prediction"] is not None else "Heuristic only (no model file)",
                    "model_confidence": result["model_confidence"],
                    "rule_score": result["risk_score"],
                    "warning_signals": "; ".join(result["reasons"]),
                    "validation": "OK",
                })
                scanned += 1
            except ValueError as exc:
                rows.append({
                    "url": raw_url,
                    "model_result": "Not analyzed",
                    "model_confidence": None,
                    "rule_score": "",
                    "warning_signals": "",
                    "validation": str(exc),
                })
                skipped += 1
        return {"rows": rows, "scanned": scanned, "skipped": skipped, "limit": 1000}
    except csv.Error as exc:
        raise HTTPException(status_code=400, detail="Could not parse the CSV file.") from exc
