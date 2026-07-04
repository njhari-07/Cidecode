"""
MITRE ATT&CK for Mobile — Full mapping (40+ techniques)
DroidRaksha P11 — replaces the small 12-entry map in narrative.py

Each entry maps a signal (permission name, obfuscation flag, YARA rule fragment,
or string keyword) to a MITRE technique.
"""
from __future__ import annotations

# ---------------------------------------------------------------------------
# Master technique registry
# ---------------------------------------------------------------------------

TECHNIQUES: dict[str, dict] = {
    # ── Collection ──────────────────────────────────────────────────────────
    "T1636.001": {
        "name": "Protected User Data: Calendar Entries",
        "tactic": "Collection",
        "signals": {"permissions": ["READ_CALENDAR"]},
    },
    "T1636.002": {
        "name": "Protected User Data: Call Logs",
        "tactic": "Collection",
        "signals": {"permissions": ["READ_CALL_LOG"]},
    },
    "T1636.003": {
        "name": "Protected User Data: Contact List",
        "tactic": "Collection",
        "signals": {"permissions": ["READ_CONTACTS"]},
    },
    "T1636.004": {
        "name": "Protected User Data: SMS Messages",
        "tactic": "Collection",
        "signals": {"permissions": ["READ_SMS", "RECEIVE_SMS"]},
    },
    "T1429": {
        "name": "Capture Audio",
        "tactic": "Collection",
        "signals": {"permissions": ["RECORD_AUDIO"]},
    },
    "T1512": {
        "name": "Video Capture",
        "tactic": "Collection",
        "signals": {"permissions": ["CAMERA"]},
    },
    "T1430": {
        "name": "Location Tracking",
        "tactic": "Collection",
        "signals": {"permissions": ["ACCESS_FINE_LOCATION", "ACCESS_COARSE_LOCATION"]},
    },
    "T1533": {
        "name": "Data from Local System",
        "tactic": "Collection",
        "signals": {"permissions": ["READ_EXTERNAL_STORAGE", "MANAGE_EXTERNAL_STORAGE"]},
    },
    "T1417": {
        "name": "Input Capture: Keylogging",
        "tactic": "Collection",
        "signals": {"permissions": ["BIND_ACCESSIBILITY_SERVICE", "BIND_INPUT_METHOD"]},
    },
    "T1517": {
        "name": "Access Notifications",
        "tactic": "Collection",
        "signals": {"permissions": ["BIND_NOTIFICATION_LISTENER_SERVICE"]},
    },

    # ── Command and Control ──────────────────────────────────────────────────
    "T1437": {
        "name": "Application Layer Protocol: Web Protocols",
        "tactic": "Command and Control",
        "signals": {"permissions": ["INTERNET"]},
    },
    "T1481.001": {
        "name": "Web Service: Dead Drop Resolver",
        "tactic": "Command and Control",
        "signals": {"yara_keywords": ["telegram", "firebase_exfil", "c2_beacon"]},
    },
    "T1481.003": {
        "name": "Web Service: One-Way Communication",
        "tactic": "Command and Control",
        "signals": {"yara_keywords": ["firebase", "fcm", "push_notification_c2"]},
    },
    "T1509": {
        "name": "Non-Standard Port",
        "tactic": "Command and Control",
        "signals": {"string_keywords": ["4444", "31337", "8443", "9001"]},
    },
    "T1573": {
        "name": "Encrypted Channel",
        "tactic": "Command and Control",
        "signals": {"string_keywords": ["aes", "rsa", "ssl", "tls", "cipher"]},
    },

    # ── Persistence ─────────────────────────────────────────────────────────
    "T1624.001": {
        "name": "Boot or Logon Initialization: Broadcast Receivers",
        "tactic": "Persistence",
        "signals": {"permissions": ["RECEIVE_BOOT_COMPLETED"]},
    },
    "T1603": {
        "name": "Scheduled Task / Job",
        "tactic": "Persistence",
        "signals": {"permissions": ["SCHEDULE_EXACT_ALARM", "WAKE_LOCK"]},
    },
    "T1398": {
        "name": "Pre-OS Boot",
        "tactic": "Persistence",
        "signals": {"yara_keywords": ["root_exploit", "bootkit"]},
    },

    # ── Privilege Escalation ─────────────────────────────────────────────────
    "T1626": {
        "name": "Abuse Elevation Control Mechanism: Device Administrator",
        "tactic": "Privilege Escalation",
        "signals": {"permissions": ["BIND_DEVICE_ADMIN"]},
    },
    "T1404": {
        "name": "Exploitation for Privilege Escalation (Root)",
        "tactic": "Privilege Escalation",
        "signals": {"yara_keywords": ["root_exploit_attempt", "su_binary"]},
    },

    # ── Defense Evasion ──────────────────────────────────────────────────────
    "T1407": {
        "name": "Download New Code at Runtime",
        "tactic": "Defense Evasion",
        "signals": {"obfuscation_flags": ["has_dex_classloader"]},
    },
    "T1406": {
        "name": "Obfuscated Files or Information",
        "tactic": "Defense Evasion",
        "signals": {"obfuscation_flags": ["has_string_encryption", "has_reflection"]},
    },
    "T1418": {
        "name": "Software Discovery: Security Software",
        "tactic": "Defense Evasion",
        "signals": {"yara_keywords": ["anti_analysis", "emulator_detect"]},
    },
    "T1627.001": {
        "name": "Execution Guardrails: Geofencing",
        "tactic": "Defense Evasion",
        "signals": {"string_keywords": ["country_code", "mcc", "mnc", "sim_country"]},
    },

    # ── Discovery ───────────────────────────────────────────────────────────
    "T1420": {
        "name": "File and Directory Discovery",
        "tactic": "Discovery",
        "signals": {"permissions": ["READ_EXTERNAL_STORAGE"]},
    },
    "T1422": {
        "name": "System Network Configuration Discovery",
        "tactic": "Discovery",
        "signals": {"permissions": ["ACCESS_NETWORK_STATE", "ACCESS_WIFI_STATE"]},
    },
    "T1424": {
        "name": "Process Discovery",
        "tactic": "Discovery",
        "signals": {"permissions": ["GET_TASKS", "REAL_GET_TASKS"]},
    },
    "T1426": {
        "name": "System Information Discovery",
        "tactic": "Discovery",
        "signals": {"permissions": ["READ_PHONE_STATE"]},
    },

    # ── Exfiltration ─────────────────────────────────────────────────────────
    "T1646": {
        "name": "Exfiltration Over C2 Channel",
        "tactic": "Exfiltration",
        "signals": {"yara_keywords": ["exfil_telegram", "firebase_data_exfil", "call_log_harvest"]},
    },
    "T1532": {
        "name": "Archive Collected Data",
        "tactic": "Exfiltration",
        "signals": {"string_keywords": ["zip", "tar", "compress", "encrypt_upload"]},
    },

    # ── Impact ────────────────────────────────────────────────────────────────
    "T1641.001": {
        "name": "Data Manipulation: Transmitted Data Manipulation",
        "tactic": "Impact",
        "signals": {"permissions": ["WRITE_SETTINGS", "CHANGE_NETWORK_STATE"]},
    },
    "T1661": {
        "name": "Input Injection",
        "tactic": "Impact",
        "signals": {"permissions": ["SYSTEM_ALERT_WINDOW", "INJECT_EVENTS"]},
    },
    "T1448": {
        "name": "Carrier Billing Fraud",
        "tactic": "Impact",
        "signals": {"permissions": ["SEND_SMS", "CALL_PHONE"]},
    },
    "T1582": {
        "name": "SMS Control",
        "tactic": "Impact",
        "signals": {"permissions": ["SEND_SMS", "RECEIVE_SMS"]},
    },
    "T1640": {
        "name": "Account Access Removal (Ransomware)",
        "tactic": "Impact",
        "signals": {"yara_keywords": ["ransomware", "file_encrypt", "locker"]},
    },
    "T1616": {
        "name": "Call Control",
        "tactic": "Impact",
        "signals": {"permissions": ["PROCESS_OUTGOING_CALLS", "ANSWER_PHONE_CALLS"]},
    },

    # ── Initial Access ────────────────────────────────────────────────────────
    "T1476": {
        "name": "Deliver Malicious App via Authorized App Store Masquerade",
        "tactic": "Initial Access",
        "signals": {"yara_keywords": ["fake_irctc", "fake_cowin", "fake_trai", "fake_income_tax"]},
    },
    "T1458": {
        "name": "Replication Through Removable Media",
        "tactic": "Initial Access",
        "signals": {"permissions": ["READ_EXTERNAL_STORAGE", "WRITE_EXTERNAL_STORAGE"]},
    },

    # ── Credential Access ─────────────────────────────────────────────────────
    "T1417.001": {
        "name": "Input Capture: GUI Input Capture (Overlay)",
        "tactic": "Credential Access",
        "signals": {"permissions": ["SYSTEM_ALERT_WINDOW", "BIND_ACCESSIBILITY_SERVICE"]},
    },
    "T1212": {
        "name": "Exploitation for Credential Access",
        "tactic": "Credential Access",
        "signals": {"yara_keywords": ["banking_trojan_overlay", "whatsapp_data_steal"]},
    },

    # ── Lateral Movement ─────────────────────────────────────────────────────
    "T1474": {
        "name": "Supply Chain Compromise",
        "tactic": "Lateral Movement",
        "signals": {"yara_keywords": ["native_dropper", "packed_dex_dropper"]},
    },
}


# ---------------------------------------------------------------------------
# Mapping function
# ---------------------------------------------------------------------------

def get_mitre_tactics(
    manifest: dict,
    obfuscation: dict,
    yara: dict,
    strings: dict | None = None,
) -> list[dict]:
    """
    Map analysis findings to MITRE ATT&CK Mobile techniques.
    Returns up to 40 matched techniques, deduplicated.
    """
    if strings is None:
        strings = {}

    perm_names = {
        p.get("name", "").split(".")[-1]
        for p in manifest.get("permissions", [])
    }
    yara_rules_lower = {
        h.get("rule", "").lower() for h in yara.get("matches", [])
    }
    obf_flags = {k for k, v in obfuscation.items() if v is True}
    string_vals_lower: set[str] = set()
    for key in ("suspicious_strings", "urls"):
        for item in strings.get(key, []):
            string_vals_lower.add(item.get("value", "").lower())

    matched: list[dict] = []
    seen_tids: set[str] = set()

    for tid, technique in TECHNIQUES.items():
        if tid in seen_tids:
            continue

        sigs = technique.get("signals", {})
        evidence_parts: list[str] = []

        # Permission signals
        for perm_sig in sigs.get("permissions", []):
            if perm_sig in perm_names:
                evidence_parts.append(f"Permission: android.permission.{perm_sig}")

        # Obfuscation signals
        for flag in sigs.get("obfuscation_flags", []):
            if flag in obf_flags:
                evidence_parts.append(f"Obfuscation: {flag}")

        # YARA keyword signals
        for kw in sigs.get("yara_keywords", []):
            for rule in yara_rules_lower:
                if kw.lower() in rule:
                    evidence_parts.append(f"YARA rule: {rule}")
                    break

        # String keyword signals
        for kw in sigs.get("string_keywords", []):
            for s in string_vals_lower:
                if kw.lower() in s:
                    evidence_parts.append(f"String: {kw}")
                    break

        if evidence_parts:
            seen_tids.add(tid)
            matched.append({
                "technique_id": tid,
                "name": technique["name"],
                "tactic": technique["tactic"],
                "evidence": evidence_parts[0],  # lead evidence
                "all_evidence": evidence_parts,
            })

    # Sort by tactic priority
    TACTIC_ORDER = [
        "Initial Access", "Persistence", "Privilege Escalation",
        "Defense Evasion", "Credential Access", "Discovery",
        "Lateral Movement", "Collection", "Command and Control",
        "Exfiltration", "Impact",
    ]
    matched.sort(key=lambda x: TACTIC_ORDER.index(x["tactic"]) if x["tactic"] in TACTIC_ORDER else 99)

    return matched[:40]
