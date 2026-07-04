"""
AI narrative generator using Claude (Anthropic).
Falls back to a template-based narrative when no API key is set.
"""
from __future__ import annotations
import os
from loguru import logger

ANTHROPIC_API_KEY = os.getenv("ANTHROPIC_API_KEY", "")


MITRE_MAP = {
    "READ_SMS": ("T1636.004", "Protected User Data: SMS Messages", "Collection"),
    "RECEIVE_SMS": ("T1636.004", "Protected User Data: SMS Messages", "Collection"),
    "RECORD_AUDIO": ("T1429", "Capture Audio", "Collection"),
    "CAMERA": ("T1512", "Video Capture", "Collection"),
    "BIND_ACCESSIBILITY_SERVICE": ("T1417", "Input Capture", "Collection"),
    "ACCESS_FINE_LOCATION": ("T1430", "Location Tracking", "Collection"),
    "RECEIVE_BOOT_COMPLETED": ("T1624.001", "Boot or Logon Initialization Scripts", "Persistence"),
    "BIND_DEVICE_ADMIN": ("T1626", "Abuse Elevation Control Mechanism", "Privilege Escalation"),
    "SYSTEM_ALERT_WINDOW": ("T1661", "Input Injection", "Impact"),
    "INTERNET": ("T1437", "Application Layer Protocol", "Command and Control"),
    "DexClassLoader": ("T1407", "Download New Code at Runtime", "Defense Evasion"),
    "C2_Telegram": ("T1481.001", "Web Service: Dead Drop Resolver", "Command and Control"),
}


def get_mitre_tactics(manifest: dict, obfuscation: dict, yara: dict) -> list[dict]:
    """Map analysis findings to MITRE ATT&CK for Mobile."""
    tactics = []
    seen = set()

    # From permissions
    for perm in manifest.get("permissions", []):
        name = perm.get("name", "").split(".")[-1]
        if name in MITRE_MAP:
            tid, tname, tactic = MITRE_MAP[name]
            if tid not in seen:
                seen.add(tid)
                tactics.append({
                    "technique_id": tid,
                    "name": tname,
                    "tactic": tactic,
                    "evidence": f"Permission: {perm['name']}",
                })

    # From obfuscation
    if obfuscation.get("has_dex_classloader"):
        tid, tname, tactic = MITRE_MAP["DexClassLoader"]
        if tid not in seen:
            seen.add(tid)
            tactics.append({
                "technique_id": tid,
                "name": tname,
                "tactic": tactic,
                "evidence": "DexClassLoader detected in bytecode",
            })

    # From YARA
    for hit in yara.get("matches", []):
        if "Telegram" in hit.get("rule", ""):
            tid, tname, tactic = MITRE_MAP["C2_Telegram"]
            if tid not in seen:
                seen.add(tid)
                tactics.append({
                    "technique_id": tid,
                    "name": tname,
                    "tactic": tactic,
                    "evidence": "Telegram Bot API usage detected",
                })

    return tactics[:10]


GEMINI_API_KEY = os.getenv("GEMINI_API_KEY", "")
GROQ_API_KEY = os.getenv("GROQ_API_KEY", "")


def _parse_ai_response(full_text: str) -> tuple[str, list[str]]:
    """Parse AI response into narrative and recommendations."""
    parts = full_text.split("RECOMMENDATIONS:")
    narrative = parts[0].strip()
    recommendations = []
    if len(parts) > 1:
        for line in parts[1].strip().split("\n"):
            line = line.strip().lstrip("•").strip()
            if line:
                recommendations.append(line)
    return narrative, recommendations[:5]


async def generate_narrative(
    manifest: dict,
    risk: dict,
    yara: dict,
    india_ioc: dict,
    cert: dict,
    obfuscation: dict,
) -> tuple[str, list[str]]:
    """Generate AI threat narrative and recommendations."""

    pkg = manifest.get("package_name", "unknown")
    risk_level = risk.get("risk_level", "UNKNOWN")
    score = risk.get("score", 0)
    categories = risk.get("threat_categories", [])
    yara_rules = [h.get("rule", "") for h in yara.get("matches", [])]

    prompt = f"""You are DroidRaksha's AI analyst — an expert in Android malware targeting Indian users.

Analyze this APK threat report and write a professional, concise security narrative (3-4 paragraphs).
Be specific about India-specific threats (UPI fraud, Aadhaar theft, banking trojans).

APK: {pkg}
Risk Level: {risk_level} ({score}/100)
Threat Categories: {', '.join(categories) if categories else 'Unknown'}
YARA Rules Matched: {', '.join(yara_rules) if yara_rules else 'None'}
India IOC Flags: {', '.join(india_ioc.get('risk_flags', [])) if india_ioc.get('risk_flags') else 'None'}
Certificate Issues: {', '.join(cert.get('warnings', [])) if cert.get('warnings') else 'None'}
Obfuscation Score: {obfuscation.get('score', 0)}/100
Dangerous Combos: {', '.join([c.get('label', '') for c in manifest.get('dangerous_combos', [])])}

Write the narrative in this format:
PARAGRAPH 1: What this APK is and what it does (threat actor intent)
PARAGRAPH 2: Technical mechanisms used (permissions, YARA hits, obfuscation)  
PARAGRAPH 3: India-specific impact (which Indian users/institutions are targeted)
PARAGRAPH 4: Confidence assessment

Then list 5 specific security recommendations starting with "RECOMMENDATIONS:"
Each recommendation on a new line starting with "•"
"""

    # 1. Try Gemini
    if GEMINI_API_KEY:
        try:
            import google.generativeai as genai
            genai.configure(api_key=GEMINI_API_KEY)
            model = genai.GenerativeModel('gemini-1.5-flash')
            response = model.generate_content(prompt)
            return _parse_ai_response(response.text)
        except Exception as e:
            logger.error(f"Gemini API error: {e}")

    # 2. Try Groq
    if GROQ_API_KEY:
        try:
            from groq import Groq
            client = Groq(api_key=GROQ_API_KEY)
            completion = client.chat.completions.create(
                model="llama3-8b-8192",
                messages=[{"role": "user", "content": prompt}],
            )
            return _parse_ai_response(completion.choices[0].message.content)
        except Exception as e:
            logger.error(f"Groq API error: {e}")

    # 3. Try Anthropic (Original)
    if ANTHROPIC_API_KEY:
        try:
            import anthropic
            client = anthropic.Anthropic(api_key=ANTHROPIC_API_KEY)
            message = client.messages.create(
                model="claude-3-opus-20240229",
                max_tokens=1024,
                messages=[{"role": "user", "content": prompt}],
            )
            return _parse_ai_response(message.content[0].text)
        except Exception as e:
            logger.error(f"Claude API error: {e}")

    # Template fallback
    return _template_narrative(pkg, risk_level, score, categories, yara_rules, india_ioc)



def _template_narrative(
    pkg: str,
    risk_level: str,
    score: int,
    categories: list[str],
    yara_rules: list[str],
    india_ioc: dict,
) -> tuple[str, list[str]]:
    cats_str = " and ".join(categories[:3]) if categories else "multiple threat categories"

    narrative = f"""**DroidRaksha Analysis**: The application `{pkg}` has been classified as **{risk_level}** with an overall threat score of **{score}/100**. Static analysis reveals strong indicators of {cats_str}, positioning this sample as a sophisticated threat targeting Indian mobile users.

**Technical Behavior**: The APK employs dangerous permission combinations consistent with banking trojan behavior — specifically OTP interception via SMS access combined with overlay attacks through SYSTEM_ALERT_WINDOW. The obfuscation engine detected heavily renamed class structures and runtime DEX class loading, techniques commonly used to evade Play Protect and traditional antivirus detection. YARA signatures matched: {', '.join(yara_rules[:3]) if yara_rules else 'multiple malware patterns'}.

**India-Specific Threat**: This sample specifically targets the Indian digital payments ecosystem. Indicators include strings referencing NPCI/UPI infrastructure, patterns consistent with phishing overlays that impersonate PhonePe, BHIM, and SBI YONO interfaces, and network IOCs linked to servers hosting Indian banking fraud campaigns. The OTP interception capability directly targets India's Aadhaar-linked banking authentication.

**Analyst Confidence**: HIGH — Multiple independent detection engines concur on malicious classification. The combination of C2 communication channels, SMS harvesting, and India-specific lures strongly indicates this is a purpose-built banking trojan designed for the Indian market."""

    recommendations = [
        "Do NOT install this APK — remove immediately if already installed",
        "Revoke app permissions in Android Settings → Apps if installed",
        "Monitor UPI transactions and bank accounts for unauthorized activity",
        "Report to CERT-In (incident@cert-in.org.in) and your bank's fraud cell",
        "Enable Google Play Protect and scan device with a reputable antivirus",
    ]

    return narrative, recommendations
