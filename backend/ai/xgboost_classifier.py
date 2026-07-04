"""
XGBoost Malware Classifier — DroidRaksha P11
=============================================
Implements feature extraction compatible with CICMalDroid 2020 dataset,
XGBoost inference, and SHAP explainability.

Model file: models/xgboost_maldroid.pkl
Feature map: models/feature_columns.json

If no trained model exists, returns a graceful fallback so the rest
of the pipeline continues uninterrupted.
"""
from __future__ import annotations
import json
import os
import time
from pathlib import Path
from typing import Optional

import numpy as np
from loguru import logger

# ── Paths ────────────────────────────────────────────────────────────────────
BASE_DIR       = Path(__file__).resolve().parents[2]
MODEL_PATH     = BASE_DIR / "models" / "xgboost_maldroid.pkl"
FEAT_PATH      = BASE_DIR / "models" / "feature_columns.json"
IMPUTER_PATH   = BASE_DIR / "models" / "median_imputer.pkl"
SCALER_PATH    = BASE_DIR / "models" / "minmax_scaler.pkl"
LABEL_MAP_PATH = BASE_DIR / "models" / "label_map.json"

# ── Lazy-loaded globals ───────────────────────────────────────────────────────
_model    = None
_imputer  = None
_scaler   = None
_explainer = None
_feature_columns: Optional[list[str]] = None

# ── MalDroid 2020 class labels ────────────────────────────────────────────────
CLASSES = ["Adware", "Banking", "SMS_Malware", "Riskware", "Benign"]

# ── Known Android permissions (subset of 215 MalDroid features) ───────────────
KNOWN_PERMISSIONS = [
    "READ_SMS", "RECEIVE_SMS", "SEND_SMS", "READ_CONTACTS", "READ_CALL_LOG",
    "RECORD_AUDIO", "CAMERA", "ACCESS_FINE_LOCATION", "ACCESS_COARSE_LOCATION",
    "READ_EXTERNAL_STORAGE", "WRITE_EXTERNAL_STORAGE", "MANAGE_EXTERNAL_STORAGE",
    "INTERNET", "ACCESS_NETWORK_STATE", "ACCESS_WIFI_STATE",
    "RECEIVE_BOOT_COMPLETED", "WAKE_LOCK", "FOREGROUND_SERVICE",
    "SYSTEM_ALERT_WINDOW", "INJECT_EVENTS",
    "BIND_ACCESSIBILITY_SERVICE", "BIND_DEVICE_ADMIN", "BIND_INPUT_METHOD",
    "BIND_NOTIFICATION_LISTENER_SERVICE", "BIND_VPN_SERVICE",
    "REQUEST_INSTALL_PACKAGES", "INSTALL_PACKAGES", "DELETE_PACKAGES",
    "READ_PHONE_STATE", "CALL_PHONE", "PROCESS_OUTGOING_CALLS", "ANSWER_PHONE_CALLS",
    "GET_TASKS", "REAL_GET_TASKS", "KILL_BACKGROUND_PROCESSES",
    "CHANGE_NETWORK_STATE", "CHANGE_WIFI_STATE",
    "WRITE_SETTINGS", "WRITE_SECURE_SETTINGS", "CHANGE_CONFIGURATION",
    "REBOOT", "MOUNT_UNMOUNT_FILESYSTEMS",
    "READ_LOGS", "DUMP",
    "VIBRATE", "FLASHLIGHT",
    "NFC", "BLUETOOTH", "BLUETOOTH_ADMIN",
    "USE_BIOMETRIC", "USE_FINGERPRINT",
    "SCHEDULE_EXACT_ALARM", "USE_EXACT_ALARM",
    "UPDATE_DEVICE_STATS", "DEVICE_POWER",
    "MASTER_CLEAR", "FACTORY_RESET",
    "SEND_RESPOND_VIA_MESSAGE",
]

# ── Known sensitive API call indicators (from strings / obfuscation) ──────────
SENSITIVE_APIS = [
    "dex_classloader", "reflection", "string_encryption", "native_code",
    "runtime_exec", "getimei", "getsimserialnum", "getdeviceid",
    "getaccounts", "getlastknownlocation", "requestlocationupdates",
    "sendtextmessage", "getinputstream", "httpurlconnection",
    "base64decode", "cipher_init", "secretkeyspec",
    "contentresolver_query", "getreadabledatabase",
    "mediarecorder_start", "camera_open",
]

# ── Intent / receiver features ────────────────────────────────────────────────
INTENT_FEATURES = [
    "has_boot_receiver", "has_sms_receiver", "has_call_receiver",
    "has_admin_receiver", "has_notification_listener",
    "has_accessibility_service", "has_vpn_service",
    "has_foreground_service", "has_device_admin",
]

# ── Full feature list ─────────────────────────────────────────────────────────
ALL_FEATURES = (
    [f"perm_{p}" for p in KNOWN_PERMISSIONS] +
    [f"api_{a}" for a in SENSITIVE_APIS] +
    INTENT_FEATURES +
    [
        "obfuscation_score",
        "dangerous_combo_count",
        "yara_critical_count",
        "yara_high_count",
        "yara_medium_count",
        "yara_low_count",
        "india_ioc_score",
        "url_count",
        "ip_count",
        "suspicious_string_count",
    ]
)


# ── Feature extraction ────────────────────────────────────────────────────────

def extract_maldroid_features(
    manifest: dict,
    strings: dict,
    yara: dict,
    obfuscation: dict,
    india_ioc: dict | None = None,
    apk_path: str | None = None,
) -> np.ndarray:
    """
    Extract a feature vector compatible with CICMalDroid 2020.
    Returns shape (1, 470) for XGBoost predict.
    """
    global _feature_columns
    _load_model()  # Ensure models/feature_columns.json is loaded

    if _feature_columns is None:
        logger.warning("No feature columns loaded. Returning 470 zeros.")
        return np.zeros((1, 470), dtype=np.float32)

    feat = {f: 0.0 for f in _feature_columns}

    if apk_path and os.path.exists(apk_path):
        try:
            from androguard.misc import AnalyzeAPK
            from collections import Counter
            
            logger.info(f"Extracting 470 features from APK for ML models...")
            a, d, dx = AnalyzeAPK(apk_path)
            
            all_dex_strings = []
            for dex in d:
                for s in dex.get_strings():
                    all_dex_strings.append(str(s))
                    
            string_counts = Counter(all_dex_strings)
            
            # Count occurrences of method/syscall names referenced or defined
            for method in dx.get_methods():
                string_counts[method.name] += 1
                
            # Count permissions
            perms = {p.get("name", "").split(".")[-1] for p in manifest.get("permissions", [])}
            for p in perms:
                string_counts[p] += 1
                
            # Map values to the 470 columns
            for f in _feature_columns:
                feat[f] = float(string_counts.get(f, 0.0))
                
            logger.info("Successfully extracted 470 features using androguard.")
        except Exception as e:
            logger.warning(f"Androguard feature extraction failed: {e}. Using zero/default fallback.")
    else:
        logger.warning("No apk_path provided to extract_maldroid_features. Using fallback values.")

    # Build ordered numpy array matching feature columns
    vector = np.array([[feat[f] for f in _feature_columns]], dtype=np.float32)
    return vector


# ── Model loading ─────────────────────────────────────────────────────────────

def _load_model():
    global _model, _imputer, _scaler, _explainer, _feature_columns
    if _model is not None:
        return True

    if not MODEL_PATH.exists():
        logger.warning(f"XGBoost model not found at {MODEL_PATH}. Run the training script first.")
        return False

    try:
        import joblib
        _model = joblib.load(MODEL_PATH)
        logger.info("XGBoost model loaded successfully.")

        # Load preprocessing pipeline artifacts (produced by model training.py)
        if IMPUTER_PATH.exists():
            _imputer = joblib.load(IMPUTER_PATH)
            logger.info("Median imputer loaded.")
        else:
            logger.warning(f"Imputer not found at {IMPUTER_PATH} — skipping imputation.")

        if SCALER_PATH.exists():
            _scaler = joblib.load(SCALER_PATH)
            logger.info("MinMax scaler loaded.")
        else:
            logger.warning(f"Scaler not found at {SCALER_PATH} — skipping scaling.")

        if FEAT_PATH.exists():
            with open(FEAT_PATH) as f:
                _feature_columns = json.load(f)

        # Build SHAP explainer
        try:
            import shap
            _explainer = shap.TreeExplainer(_model)
            logger.info("SHAP TreeExplainer initialised.")
        except ImportError:
            logger.warning("shap not installed — SHAP explanations disabled.")
        except Exception as e:
            logger.warning(f"SHAP explainer error: {e}")

        return True
    except Exception as e:
        logger.error(f"Failed to load XGBoost model: {e}")
        return False


# ── SHAP explanation ──────────────────────────────────────────────────────────

def _get_shap_explanation(feature_vector: np.ndarray, pred_class_idx: int) -> list[dict]:
    """
    Returns top-5 SHAP features driving the predicted class.
    """
    global _explainer, _feature_columns
    if _explainer is None or _feature_columns is None:
        return []

    try:
        import shap
        shap_values = _explainer.shap_values(feature_vector)

        # Newer SHAP + XGBoost returns (n_samples, n_features, n_classes)
        # Older versions return list of (n_samples, n_features) per class
        sv = np.array(shap_values)
        if sv.ndim == 3 and sv.shape[-1] > 1:
            class_shap = sv[0, :, pred_class_idx]
        elif sv.ndim == 3:
            class_shap = sv[0, :, 0]
        elif sv.ndim == 2:
            class_shap = sv[0]
        else:
            class_shap = sv.flatten()

        # Pair feature names with SHAP values
        pairs = sorted(
            zip(_feature_columns, class_shap),
            key=lambda x: abs(x[1]),
            reverse=True,
        )[:5]

        return [
            {
                "feature": name.replace("perm_", "").replace("api_", "").replace("_", " ").title(),
                "raw_name": name,
                "shap_value": round(float(val), 4),
                "direction": "increases" if val > 0 else "decreases",
            }
            for name, val in pairs
            if abs(val) > 0.001
        ]
    except Exception as e:
        logger.warning(f"SHAP computation failed: {e}")
        return []


# ── Main classify function ────────────────────────────────────────────────────

def classify(
    manifest: dict,
    strings: dict,
    yara: dict,
    obfuscation: dict,
    india_ioc: dict | None = None,
    apk_path: str | None = None,
) -> dict:
    """
    Run XGBoost classification + SHAP explanation.

    Returns:
        {
          "label": "Banking",
          "probability": 0.91,
          "class_probs": {"Adware": 0.02, "Banking": 0.91, ...},
          "shap_top5": [...],
          "available": True,
          "inference_ms": 14,
        }
    """
    t0 = time.perf_counter()

    if not _load_model():
        return {
            "label": "unavailable",
            "probability": 0.0,
            "class_probs": {c: 0.0 for c in CLASSES},
            "shap_top5": [],
            "available": False,
            "inference_ms": 0,
        }

    try:
        features = extract_maldroid_features(manifest, strings, yara, obfuscation, india_ioc, apk_path=apk_path)

        # Apply preprocessing pipeline if available (matches training-time transforms)
        if _imputer is not None:
            feat_arr = features.copy()
            feat_arr[np.isinf(feat_arr)] = np.nan
            features = _imputer.transform(feat_arr)
        if _scaler is not None:
            features = _scaler.transform(features)

        proba    = _model.predict_proba(features)[0]          # shape (n_classes,)
        pred_idx = int(np.argmax(proba))
        label    = CLASSES[pred_idx]

        shap_top5 = _get_shap_explanation(features, pred_idx)
        elapsed   = int((time.perf_counter() - t0) * 1000)

        return {
            "label": label,
            "probability": round(float(proba[pred_idx]), 4),
            "class_probs": {c: round(float(p), 4) for c, p in zip(CLASSES, proba)},
            "shap_top5": shap_top5,
            "available": True,
            "inference_ms": elapsed,
        }

    except Exception as e:
        logger.error(f"XGBoost classify failed: {e}")
        return {
            "label": "error",
            "probability": 0.0,
            "class_probs": {c: 0.0 for c in CLASSES},
            "shap_top5": [],
            "available": False,
            "inference_ms": 0,
        }

