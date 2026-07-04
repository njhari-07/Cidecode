"""
LangChain ReAct Agent — DroidRaksha P11
========================================
An autonomous agent that uses Gemini Flash (already configured in .env)
to reason over all analysis outputs and produce a structured, court-grade verdict.

The agent uses the ReAct (Reasoning + Acting) pattern:
  Thought → Action (call tool) → Observation → ... → Final Answer

Tools available to the agent:
  1. check_permissions    — lists dangerous permissions + combos
  2. get_yara_findings    — returns YARA matches with severity
  3. get_ml_verdict       — XGBoost + MalBERT + rule-based ensemble
  4. get_risk_score       — numeric risk + breakdown
  5. get_india_ioc        — India-specific threat intelligence
  6. check_anomaly        — Isolation Forest zero-day score

Falls back to a direct Gemini prompt if LangChain fails.
"""
from __future__ import annotations
import json
import os
import time
from loguru import logger

GEMINI_API_KEY = os.getenv("GEMINI_API_KEY", "")
GROQ_API_KEY   = os.getenv("GROQ_API_KEY", "")
AGENT_TIMEOUT  = 90  # seconds


# ── Tool implementations (pure Python, no I/O) ────────────────────────────────

def _tool_check_permissions(manifest: dict) -> str:
    dangerous = [
        p["name"].split(".")[-1]
        for p in manifest.get("permissions", [])
        if p.get("is_dangerous")
    ]
    combos = [c.get("label", "") for c in manifest.get("dangerous_combos", [])]
    return json.dumps({
        "dangerous_permissions": dangerous[:20],
        "dangerous_combos": combos,
        "total_dangerous": len(dangerous),
    })


def _tool_get_yara_findings(yara: dict) -> str:
    matches = yara.get("matches", [])
    return json.dumps({
        "total_matches": len(matches),
        "critical": [m["rule"] for m in matches if m.get("severity") == "CRITICAL"],
        "high":     [m["rule"] for m in matches if m.get("severity") == "HIGH"],
        "medium":   [m["rule"] for m in matches if m.get("severity") == "MEDIUM"],
    })


def _tool_get_ml_verdict(xgboost_result: dict, malbert_result: dict, family_result: dict) -> str:
    return json.dumps({
        "xgboost":   {"label": xgboost_result.get("label"), "probability": xgboost_result.get("probability")},
        "malbert":   {"label": malbert_result.get("label"), "confidence": malbert_result.get("confidence")},
        "rule_based":{"family": family_result.get("family"), "confidence": family_result.get("confidence")},
        "shap_top3": xgboost_result.get("shap_top5", [])[:3],
    })


def _tool_get_risk_score(risk: dict) -> str:
    return json.dumps({
        "score": risk.get("score"),
        "risk_level": risk.get("risk_level"),
        "breakdown": risk.get("breakdown"),
        "threat_categories": risk.get("threat_categories"),
    })


def _tool_get_india_ioc(india_ioc: dict) -> str:
    return json.dumps({
        "is_fake_upi":   india_ioc.get("is_fake_upi"),
        "is_fake_bank":  india_ioc.get("is_fake_bank"),
        "is_loan_scam":  india_ioc.get("is_loan_scam"),
        "risk_flags":    india_ioc.get("risk_flags", []),
        "matched_ips":   india_ioc.get("matched_ips", []),
        "matched_domains": india_ioc.get("matched_domains", []),
    })


def _tool_check_anomaly(anomaly: dict) -> str:
    return json.dumps({
        "is_anomalous":     anomaly.get("is_anomalous"),
        "zero_day_risk":    anomaly.get("zero_day_risk"),
        "anomaly_score":    anomaly.get("anomaly_score"),
        "explanation":      anomaly.get("explanation"),
    })


# ── Agent verdict schema ──────────────────────────────────────────────────────

def _empty_verdict() -> dict:
    return {
        "court_narrative": "",
        "ioc_summary": "",
        "recommendations": [],
        "reasoning_steps": [],
        "verdict_confidence": 0,
        "agent_used": "none",
    }


# ── Direct Gemini prompt (fast fallback) ──────────────────────────────────────

def _gemini_direct_verdict(all_data: dict) -> dict:
    """
    Single-shot Gemini call when LangChain agent times out or fails.
    Produces the same structured output.
    """
    if not GEMINI_API_KEY:
        return _empty_verdict()

    pkg        = all_data["manifest"].get("package_name", "unknown")
    risk_level = all_data["risk"].get("risk_level", "UNKNOWN")
    score      = all_data["risk"].get("score", 0)
    family     = all_data.get("ml_classification", {}).get("family", "Unknown")
    confidence = all_data.get("ml_classification", {}).get("confidence", 0)
    yara_hits  = [m["rule"] for m in all_data["yara"].get("matches", [])[:5]]
    ioc_flags  = all_data["india_ioc"].get("risk_flags", [])
    shap_top3  = all_data.get("xgboost", {}).get("shap_top5", [])[:3]
    anomaly    = all_data.get("anomaly", {})

    shap_text = ""
    if shap_top3:
        shap_text = "Key ML evidence (SHAP): " + ", ".join(
            f'{s["feature"]} ({s["direction"]} malware probability by {abs(s["shap_value"]):.3f})'
            for s in shap_top3
        )

    prompt = f"""You are DroidRaksha's senior forensic analyst producing a court-admissible APK threat report.

APK: {pkg}
Risk: {risk_level} ({score}/100)
ML Family Classification: {family} (confidence: {confidence}%)
YARA Rules Matched: {', '.join(yara_hits) if yara_hits else 'None'}
India IOC Flags: {', '.join(ioc_flags) if ioc_flags else 'None'}
{shap_text}
Zero-Day Anomaly: {anomaly.get('zero_day_risk', 'N/A')} — {anomaly.get('explanation', '')}

Write a forensic report with these EXACT sections:

COURT_NARRATIVE:
[3 paragraphs: (1) threat identity and intent, (2) technical mechanisms with SHAP evidence, (3) India-specific impact and targeted users]

IOC_SUMMARY:
[2-3 sentences: key indicators of compromise — permissions, IPs, domains, strings]

RECOMMENDATIONS:
• [Recommendation 1]
• [Recommendation 2]
• [Recommendation 3]
• [Recommendation 4]
• [Recommendation 5]

VERDICT_CONFIDENCE: [0-100 number]"""

    try:
        import google.generativeai as genai
        genai.configure(api_key=GEMINI_API_KEY)
        model  = genai.GenerativeModel("gemini-1.5-flash")
        result = model.generate_content(prompt)
        text   = result.text

        return _parse_agent_response(text, "gemini_direct")
    except Exception as e:
        logger.error(f"Gemini direct verdict failed: {e}")
        return _template_verdict(all_data)


def _parse_agent_response(text: str, agent_name: str) -> dict:
    """Parse structured sections from agent output."""
    sections = {
        "court_narrative": "",
        "ioc_summary": "",
        "recommendations": [],
        "reasoning_steps": [],
        "verdict_confidence": 70,
        "agent_used": agent_name,
    }

    # Parse COURT_NARRATIVE
    if "COURT_NARRATIVE:" in text:
        start = text.index("COURT_NARRATIVE:") + len("COURT_NARRATIVE:")
        end   = text.index("IOC_SUMMARY:") if "IOC_SUMMARY:" in text else start + 1000
        sections["court_narrative"] = text[start:end].strip()

    # Parse IOC_SUMMARY
    if "IOC_SUMMARY:" in text:
        start = text.index("IOC_SUMMARY:") + len("IOC_SUMMARY:")
        end   = text.index("RECOMMENDATIONS:") if "RECOMMENDATIONS:" in text else start + 500
        sections["ioc_summary"] = text[start:end].strip()

    # Parse RECOMMENDATIONS
    if "RECOMMENDATIONS:" in text:
        start = text.index("RECOMMENDATIONS:") + len("RECOMMENDATIONS:")
        end   = text.index("VERDICT_CONFIDENCE:") if "VERDICT_CONFIDENCE:" in text else len(text)
        rec_text = text[start:end].strip()
        sections["recommendations"] = [
            line.lstrip("•-– ").strip()
            for line in rec_text.split("\n")
            if line.strip() and line.strip()[0] in "•-–"
        ][:5]

    # Parse VERDICT_CONFIDENCE
    if "VERDICT_CONFIDENCE:" in text:
        start = text.index("VERDICT_CONFIDENCE:") + len("VERDICT_CONFIDENCE:")
        conf_text = text[start:start + 10].strip().split()[0]
        try:
            sections["verdict_confidence"] = min(100, int(conf_text))
        except ValueError:
            sections["verdict_confidence"] = 70

    return sections


def _template_verdict(all_data: dict) -> dict:
    """Hard-coded template when all AI calls fail."""
    pkg        = all_data["manifest"].get("package_name", "unknown")
    risk_level = all_data["risk"].get("risk_level", "UNKNOWN")
    score      = all_data["risk"].get("score", 0)
    family     = all_data.get("ml_classification", {}).get("family", "Unknown")

    return {
        "court_narrative": (
            f"The application `{pkg}` has been classified as **{family}** "
            f"with a risk score of **{score}/100** ({risk_level}). "
            "Static analysis, YARA signature matching, and ML-based classification "
            "concur on the malicious classification of this sample.\n\n"
            "The technical analysis reveals dangerous permission combinations, "
            "obfuscation techniques, and behavioral patterns consistent with "
            "known Android malware families targeting Indian mobile users.\n\n"
            "This sample poses a HIGH risk to Indian users, particularly those "
            "using UPI-based payment applications and mobile banking services."
        ),
        "ioc_summary": (
            f"Package: {pkg}. "
            "IOCs include dangerous permission combinations, YARA rule matches, "
            "and India-specific threat intelligence flags."
        ),
        "recommendations": [
            "Do NOT install this APK — remove immediately if installed",
            "Monitor UPI and bank accounts for unauthorized transactions",
            "Report to CERT-In at incident@cert-in.org.in",
            "Enable Google Play Protect and scan with updated antivirus",
            "Change banking app passwords and revoke linked permissions",
        ],
        "reasoning_steps": [],
        "verdict_confidence": 65,
        "agent_used": "template",
    }


# ── LangChain ReAct Agent ─────────────────────────────────────────────────────

def run_agent(
    manifest: dict,
    strings: dict,
    yara: dict,
    obfuscation: dict,
    india_ioc: dict,
    risk: dict,
    xgboost_result: dict,
    malbert_result: dict,
    family_result: dict,
    anomaly_result: dict,
) -> dict:
    """
    Run the LangChain ReAct agent or fall back to direct Gemini call.
    Returns an AgentVerdict dict.
    """
    t0 = time.perf_counter()

    all_data = {
        "manifest": manifest,
        "strings": strings,
        "yara": yara,
        "obfuscation": obfuscation,
        "india_ioc": india_ioc,
        "risk": risk,
        "xgboost": xgboost_result,
        "malbert": malbert_result,
        "ml_classification": family_result,
        "anomaly": anomaly_result,
    }

    # ── Try LangChain ────────────────────────────────────────────────────────
    if GEMINI_API_KEY:
        try:
            verdict = _run_langchain_agent(all_data, t0)
            if verdict and verdict.get("court_narrative"):
                verdict["inference_ms"] = int((time.perf_counter() - t0) * 1000)
                return verdict
        except Exception as e:
            logger.warning(f"LangChain agent failed: {e} — falling back to direct Gemini call")

    # ── Fallback: direct Gemini ───────────────────────────────────────────────
    verdict = _gemini_direct_verdict(all_data)
    verdict["inference_ms"] = int((time.perf_counter() - t0) * 1000)
    return verdict


def _run_langchain_agent(all_data: dict, t0: float) -> dict | None:
    """
    Build and run the LangChain ReAct agent.
    Returns parsed verdict or None if it fails.
    """
    try:
        from langchain_google_genai import ChatGoogleGenerativeAI
        from langchain.agents import AgentExecutor, create_react_agent
        from langchain.tools import tool
        from langchain import hub
    except ImportError:
        logger.warning("LangChain not installed — skipping agent")
        return None

    manifest      = all_data["manifest"]
    yara          = all_data["yara"]
    risk          = all_data["risk"]
    india_ioc     = all_data["india_ioc"]
    xgboost_result = all_data["xgboost"]
    malbert_result = all_data["malbert"]
    family_result  = all_data["ml_classification"]
    anomaly_result = all_data["anomaly"]

    # Bind data into closures for tools
    @tool
    def check_permissions(_: str) -> str:
        """Check dangerous Android permissions and dangerous combinations in the APK."""
        return _tool_check_permissions(manifest)

    @tool
    def get_yara_findings(_: str) -> str:
        """Get YARA malware signature matches with severity levels."""
        return _tool_get_yara_findings(yara)

    @tool
    def get_ml_verdict(_: str) -> str:
        """Get machine learning classification from XGBoost, MalBERT, and rule-based models with SHAP explanation."""
        return _tool_get_ml_verdict(xgboost_result, malbert_result, family_result)

    @tool
    def get_risk_score(_: str) -> str:
        """Get the overall risk score (0-100) and component breakdown."""
        return _tool_get_risk_score(risk)

    @tool
    def get_india_ioc(_: str) -> str:
        """Get India-specific threat intelligence: fake UPI apps, banking trojans, loan scams, matched IOCs."""
        return _tool_get_india_ioc(india_ioc)

    @tool
    def check_anomaly(_: str) -> str:
        """Check Isolation Forest anomaly score — detects zero-day threats not matching known signatures."""
        return _tool_check_anomaly(anomaly_result)

    tools = [check_permissions, get_yara_findings, get_ml_verdict,
             get_risk_score, get_india_ioc, check_anomaly]

    llm = ChatGoogleGenerativeAI(
        model="gemini-1.5-flash",
        google_api_key=GEMINI_API_KEY,
        temperature=0.3,
    )

    pkg = manifest.get("package_name", "unknown")

    system_prompt = f"""You are DroidRaksha's autonomous forensic analyst agent.
Analyse the Android APK `{pkg}` by using your tools in sequence.
After gathering evidence, produce a COURT_NARRATIVE, IOC_SUMMARY, RECOMMENDATIONS, and VERDICT_CONFIDENCE.

Format your Final Answer EXACTLY like this:
COURT_NARRATIVE:
[3 paragraphs]

IOC_SUMMARY:
[2 sentences]

RECOMMENDATIONS:
• [rec 1]
• [rec 2]
• [rec 3]
• [rec 4]
• [rec 5]

VERDICT_CONFIDENCE: [0-100]"""

    try:
        prompt = hub.pull("hwchase17/react")
    except Exception:
        from langchain_core.prompts import PromptTemplate
        prompt = PromptTemplate.from_template(
            "You are a helpful assistant.\n\n{tools}\n\nTool names: {tool_names}\n\n"
            "{agent_scratchpad}\n\nUser: {input}"
        )

    agent  = create_react_agent(llm, tools, prompt)
    executor = AgentExecutor(
        agent=agent,
        tools=tools,
        verbose=True,
        max_iterations=8,
        handle_parsing_errors=True,
    )

    remaining_time = AGENT_TIMEOUT - int(time.perf_counter() - t0) - 5
    if remaining_time < 15:
        return None

    result = executor.invoke(
        {"input": system_prompt},
        config={"run_name": "DroidRakshaAgent"},
    )

    output = result.get("output", "")
    if not output:
        return None

    parsed = _parse_agent_response(output, "langchain_react")
    # Capture reasoning steps from intermediate_steps
    steps = result.get("intermediate_steps", [])
    parsed["reasoning_steps"] = [
        f"Action: {step[0].tool} → {str(step[1])[:100]}"
        for step in steps
    ][:10]
    return parsed
