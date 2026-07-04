"""
Isolation Forest — Zero-Day Anomaly Detector
=============================================
Detects APKs that don't match any known malware family but exhibit
statistically anomalous behavior compared to benign apps.

This is the critical differentiator: while XGBoost classifies *known* families,
Isolation Forest flags *novel* threats that no YARA rule or signature covers.

Model file: models/isolation_forest.pkl
"""
from __future__ import annotations
import time
from pathlib import Path

import numpy as np
from loguru import logger

from backend.ai.xgboost_classifier import extract_maldroid_features

# ── Paths ─────────────────────────────────────────────────────
BASE_DIR   = Path(__file__).resolve().parents[2]
MODEL_PATH = BASE_DIR / "models" / "isolation_forest.pkl"

_model = None
ANOMALY_THRESHOLD = -0.05


def _load_model() -> bool:
    global _model
    if _model is not None:
        return True
    if not MODEL_PATH.exists():
        logger.warning(f"Isolation Forest model not found at {MODEL_PATH}. Run train script first.")
        return False
    try:
        import joblib
        _model = joblib.load(MODEL_PATH)
        logger.info("Isolation Forest model loaded.")
        return True
    except Exception as e:
        logger.error(f"Failed to load Isolation Forest: {e}")
        return False


def _heuristic_anomaly_score(
    manifest: dict,
    strings: dict,
    yara: dict,
    obfuscation: dict,
    india_ioc: dict | None,
) -> float:
    """
    Lightweight heuristic anomaly score when no trained model exists.
    Returns 0.0 (benign-ish) to 1.0 (highly anomalous).
    """
    score = 0.0
    perm_names = {p.get("name", "").split(".")[-1] for p in manifest.get("permissions", [])}

    # Dangerous permission density
    dangerous = {"READ_SMS", "RECEIVE_SMS", "RECORD_AUDIO", "CAMERA", "SYSTEM_ALERT_WINDOW",
                 "BIND_ACCESSIBILITY_SERVICE", "BIND_DEVICE_ADMIN", "REQUEST_INSTALL_PACKAGES"}
    dangerous_count = len(dangerous & perm_names)
    score += min(0.4, dangerous_count * 0.07)

    # Obfuscation
    obf = obfuscation or {}
    score += 0.1 if obf.get("has_dex_classloader") else 0.0
    score += 0.1 if obf.get("has_string_encryption") else 0.0
    score += 0.05 * min(1.0, obf.get("score", 0) / 100)

    # YARA hits indicate known pattern — reduces anomaly score (it's *known* malware)
    yara_count = len(yara.get("matches", []))
    score += 0.1 if yara_count == 0 and dangerous_count >= 3 else 0.0  # no rules matched but suspicious

    # India IOC
    ioc = india_ioc or {}
    if ioc.get("is_fake_upi") or ioc.get("is_fake_bank"):
        score += 0.15

    # High IP count with no YARA match = suspicious pattern
    ip_count = len(strings.get("ips", []))
    if ip_count > 5 and yara_count == 0:
        score += 0.1

    return min(1.0, score)


def detect(
    manifest: dict,
    strings: dict,
    yara: dict,
    obfuscation: dict,
    india_ioc: dict | None = None,
) -> dict:
    """
    Run anomaly detection.

    Returns:
        {
          "is_anomalous": True,
          "anomaly_score": -0.18,      # decision_function output
          "anomaly_percentile": 73,    # 0=normal, 100=most anomalous
          "zero_day_risk": "HIGH",     # HIGH / MEDIUM / LOW
          "explanation": "...",
          "model_used": "isolation_forest" | "heuristic",
          "available": True,
        }
    """
    t0 = time.perf_counter()

    # Try trained model first
    if _load_model():
        try:
            features = extract_maldroid_features(manifest, strings, yara, obfuscation, india_ioc)
            # predict(): 1 = normal, -1 = anomalous
            prediction  = int(_model.predict(features)[0])
            is_anomalous = (prediction == -1)

            # decision_function: positive = normal, negative = anomalous
            decision_score = float(_model.decision_function(features)[0])

            # Convert to 0-100 percentile (higher = more anomalous)
            # decision_function range varies by dataset; normalise safely
            raw_abs = abs(min(0.0, decision_score))          # 0 if normal
            percentile = int(min(100, raw_abs * 200))        # scale factor

            if is_anomalous and percentile > 50:
                risk = "CRITICAL"
            elif is_anomalous and percentile > 25:
                risk = "HIGH"
            elif is_anomalous:
                risk = "MEDIUM"
            else:
                risk = "LOW"

            explanation = _build_explanation(manifest, strings, yara, obfuscation, india_ioc, is_anomalous)

            return {
                "is_anomalous": is_anomalous,
                "anomaly_score": round(decision_score, 4),
                "anomaly_percentile": percentile,
                "zero_day_risk": risk,
                "explanation": explanation,
                "model_used": "isolation_forest",
                "available": True,
                "inference_ms": int((time.perf_counter() - t0) * 1000),
            }
        except Exception as e:
            logger.error(f"Isolation Forest inference failed: {e}")

    # Heuristic fallback
    heuristic_score = _heuristic_anomaly_score(manifest, strings, yara, obfuscation, india_ioc)
    is_anomalous = heuristic_score > 0.3
    percentile = int(heuristic_score * 100)

    if heuristic_score > 0.7:
        risk = "HIGH"
    elif heuristic_score > 0.4:
        risk = "MEDIUM"
    else:
        risk = "LOW"

    explanation = _build_explanation(manifest, strings, yara, obfuscation, india_ioc, is_anomalous)

    return {
        "is_anomalous": is_anomalous,
        "anomaly_score": round(-(heuristic_score - 0.5), 4),
        "anomaly_percentile": percentile,
        "zero_day_risk": risk,
        "explanation": explanation,
        "model_used": "heuristic",
        "available": True,
        "inference_ms": int((time.perf_counter() - t0) * 1000),
    }


def _build_explanation(
    manifest: dict,
    strings: dict,
    yara: dict,
    obfuscation: dict,
    india_ioc: dict | None,
    is_anomalous: bool,
) -> str:
    perm_names = {p.get("name", "").split(".")[-1] for p in manifest.get("permissions", [])}
    yara_count = len(yara.get("matches", []))
    obf = obfuscation or {}
    ioc = india_ioc or {}

    if not is_anomalous:
        return "Behavioral profile is consistent with benign Android applications in the training corpus."

    reasons = []
    dangerous_perms = {
        "READ_SMS", "RECEIVE_SMS", "RECORD_AUDIO", "CAMERA",
        "SYSTEM_ALERT_WINDOW", "BIND_ACCESSIBILITY_SERVICE",
        "BIND_DEVICE_ADMIN", "REQUEST_INSTALL_PACKAGES"
    }
    found = dangerous_perms & perm_names
    if found:
        reasons.append(f"unusual permission cluster ({', '.join(list(found)[:3])})")
    if obf.get("has_dex_classloader"):
        reasons.append("runtime code loading (DexClassLoader)")
    if obf.get("has_string_encryption"):
        reasons.append("encrypted string obfuscation")
    if yara_count == 0 and len(found) >= 3:
        reasons.append("no known YARA signature match despite suspicious behavior — potential zero-day")
    if ioc.get("is_fake_upi") or ioc.get("is_fake_bank"):
        reasons.append("India-specific payment app impersonation pattern")
    ip_count = len(strings.get("ips", []))
    if ip_count > 5:
        reasons.append(f"unusually high hardcoded IP count ({ip_count})")

    if not reasons:
        reasons = ["statistical deviation from benign application baseline"]

    return "Anomalous APK detected — " + "; ".join(reasons) + "."
