"""
MalBERT-style Text Classifier — DroidRaksha P11
================================================
Implements the MalBERT approach: represent an APK as structured text
(permissions + package + YARA hits + obfuscation flags) and run a
BERT-family model for classification.

Since no official MalBERT weights are publicly available on HuggingFace,
we use facebook/bart-large-mnli for zero-shot classification — same
transformer family, no fine-tuning required, works on first run.

First call downloads ~1.6GB model to ~/.cache/huggingface/
Subsequent calls use the cached version (fast).

CPU inference: ~8–15 seconds per APK.
GPU inference: ~1–2 seconds per APK.
"""
from __future__ import annotations
import concurrent.futures
import time
from loguru import logger

# ── Model config ──────────────────────────────────────────────────────────────
HF_MODEL     = "facebook/bart-large-mnli"
TIMEOUT_SECS = 60  # max wait for inference before fallback

# ── Candidate labels (aligned with MalDroid classes + Android threat taxonomy) ─
CANDIDATE_LABELS = [
    "banking trojan",
    "SMS malware",
    "ransomware",
    "spyware and stalkerware",
    "remote access trojan",
    "dropper and loader",
    "adware",
    "riskware",
    "legitimate application",
]

# ── Family → normalised name map ─────────────────────────────────────────────
LABEL_MAP = {
    "banking trojan":             "BankingTrojan",
    "SMS malware":                "SMSMalware",
    "ransomware":                 "Ransomware",
    "spyware and stalkerware":    "Spyware",
    "remote access trojan":       "RAT",
    "dropper and loader":         "Dropper",
    "adware":                     "Adware",
    "riskware":                   "Riskware",
    "legitimate application":     "Benign",
}

_pipeline = None


def _load_pipeline():
    global _pipeline
    if _pipeline is not None:
        return _pipeline
    try:
        from transformers import pipeline
        logger.info("Loading MalBERT (facebook/bart-large-mnli) — first call downloads ~1.6GB…")
        _pipeline = pipeline(
            "zero-shot-classification",
            model=HF_MODEL,
            device=-1,  # CPU; change to 0 for GPU
        )
        logger.info("MalBERT pipeline ready.")
        return _pipeline
    except Exception as e:
        logger.error(f"Failed to load MalBERT pipeline: {e}")
        return None


def _build_input_text(
    manifest: dict,
    yara: dict,
    obfuscation: dict,
    strings: dict | None = None,
) -> str:
    """
    Serialise APK signals as structured text for the transformer.
    Mirrors the MalBERT paper approach: treat manifest + API calls as document.
    """
    parts: list[str] = []

    # Package name
    pkg = manifest.get("package_name", "unknown")
    parts.append(f"Package: {pkg}")

    # Permissions
    perms = [
        p.get("name", "").split(".")[-1]
        for p in manifest.get("permissions", [])
        if p.get("is_dangerous")
    ]
    if perms:
        parts.append(f"Dangerous permissions: {' '.join(perms[:20])}")

    # Dangerous combos
    combos = [c.get("label", "") for c in manifest.get("dangerous_combos", [])]
    if combos:
        parts.append(f"Dangerous combinations: {' | '.join(combos)}")

    # YARA matches
    rules = [h.get("rule", "") for h in yara.get("matches", [])[:10]]
    if rules:
        parts.append(f"YARA signatures matched: {' '.join(rules)}")

    # Obfuscation signals
    obf_flags = []
    if obfuscation.get("has_dex_classloader"):
        obf_flags.append("DexClassLoader")
    if obfuscation.get("has_string_encryption"):
        obf_flags.append("StringEncryption")
    if obfuscation.get("has_reflection"):
        obf_flags.append("Reflection")
    if obfuscation.get("has_native_code"):
        obf_flags.append("NativeCode")
    if obf_flags:
        parts.append(f"Obfuscation techniques: {' '.join(obf_flags)}")

    # Obfuscation score
    obf_score = obfuscation.get("score", 0)
    if obf_score > 50:
        parts.append(f"High obfuscation score: {obf_score}/100")

    # Suspicious strings sample
    if strings:
        sus = [s.get("value", "") for s in strings.get("suspicious_strings", [])[:5]]
        if sus:
            parts.append(f"Suspicious strings: {' '.join(sus)}")

    # Components
    services  = manifest.get("services", [])
    receivers = manifest.get("receivers", [])
    if services:
        parts.append(f"Services: {' '.join(services[:5])}")
    if receivers:
        parts.append(f"Receivers: {' '.join(receivers[:5])}")

    return ". ".join(parts)


def _run_inference(text: str) -> dict | None:
    """Runs inference inside a thread so we can apply timeout."""
    pipe = _load_pipeline()
    if pipe is None:
        return None
    result = pipe(text, CANDIDATE_LABELS, multi_label=False)
    return result


def classify(
    manifest: dict,
    yara: dict,
    obfuscation: dict,
    strings: dict | None = None,
) -> dict:
    """
    Run MalBERT-style zero-shot classification.

    Returns:
        {
          "label": "BankingTrojan",
          "raw_label": "banking trojan",
          "confidence": 0.87,
          "all_scores": {"banking trojan": 0.87, "legitimate application": 0.02, ...},
          "input_text_preview": "Package: com.fake.bank. Dangerous permissions: READ_SMS ...",
          "available": True,
          "inference_ms": 9200,
        }
    """
    t0 = time.perf_counter()

    input_text = _build_input_text(manifest, yara, obfuscation, strings)

    try:
        with concurrent.futures.ThreadPoolExecutor(max_workers=1) as executor:
            future = executor.submit(_run_inference, input_text)
            result = future.result(timeout=TIMEOUT_SECS)

        if result is None:
            raise RuntimeError("Pipeline returned None")

        labels  = result["labels"]
        scores  = result["scores"]
        top_raw = labels[0]
        top_conf = float(scores[0])

        all_scores = {lbl: round(float(sc), 4) for lbl, sc in zip(labels, scores)}

        return {
            "label": LABEL_MAP.get(top_raw, top_raw),
            "raw_label": top_raw,
            "confidence": round(top_conf, 4),
            "all_scores": all_scores,
            "input_text_preview": input_text[:300],
            "available": True,
            "inference_ms": int((time.perf_counter() - t0) * 1000),
        }

    except concurrent.futures.TimeoutError:
        logger.warning(f"MalBERT inference timed out after {TIMEOUT_SECS}s")
    except Exception as e:
        logger.error(f"MalBERT classify failed: {e}")

    # Fallback — lightweight keyword heuristic
    return _keyword_fallback(manifest, yara, obfuscation, t0)


def _keyword_fallback(manifest: dict, yara: dict, obfuscation: dict, t0: float) -> dict:
    """Fast keyword heuristic when transformer times out or fails."""
    perm_names = {p.get("name", "").split(".")[-1] for p in manifest.get("permissions", [])}
    rules_lower = {h.get("rule", "").lower() for h in yara.get("matches", [])}

    label = "Riskware"
    confidence = 0.45

    if "BIND_ACCESSIBILITY_SERVICE" in perm_names and "READ_SMS" in perm_names:
        label = "BankingTrojan"; confidence = 0.72
    elif "RECORD_AUDIO" in perm_names and "CAMERA" in perm_names:
        label = "RAT"; confidence = 0.65
    elif any("ransom" in r or "encrypt" in r for r in rules_lower):
        label = "Ransomware"; confidence = 0.80
    elif any("miner" in r or "xmrig" in r for r in rules_lower):
        label = "Adware"; confidence = 0.70
    elif obfuscation.get("has_dex_classloader") and "REQUEST_INSTALL_PACKAGES" in perm_names:
        label = "Dropper"; confidence = 0.68
    elif "READ_SMS" in perm_names:
        label = "SMSMalware"; confidence = 0.60

    return {
        "label": label,
        "raw_label": label.lower(),
        "confidence": confidence,
        "all_scores": {label: confidence},
        "input_text_preview": "(keyword fallback — transformer timed out)",
        "available": False,
        "inference_ms": int((time.perf_counter() - t0) * 1000),
    }
