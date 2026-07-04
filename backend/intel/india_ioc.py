"""
India-specific IOC database: checks APK against known fake UPI apps,
fraudulent domains, loan scam packages, and Indian banking trojans.
"""
from __future__ import annotations
import re

# Known malicious/fake package names targeting Indian users
FAKE_PACKAGES = {
    "com.npci.bhim.fake",
    "com.phonepe.app.fake",
    "net.one97.paytm.clone",
    "com.google.android.apps.nbu.files.fake",
    "com.amazon.mShop.android.shopping.fake",
    "in.amazon.mShop.android.shopping.scam",
    "com.whatsapp.fake",
    "com.sbi.lotusintouch.fake",
    "com.axis.mobile.fake",
    "com.icicibank.imobile.fake",
    "com.hdfcbank.mobilebanking.fake",
    "com.boi.mobile.fake",
    "org.npci.upiapp.fake",
    # Loan scam apps
    "com.fastcash.loan",
    "com.instantloan.rupee",
    "com.quickrupee.personal",
    "com.cashguru.india",
    "com.rupeefly.loan",
}

# Suspicious domains linked to Indian fraud campaigns
FRAUDULENT_DOMAINS = {
    "upi-support-helpline.com",
    "npci-help.in",
    "sbi-secure-login.com",
    "hdfc-netbanking-secure.com",
    "paytm-kyc-update.in",
    "phonepe-fraud-check.com",
    "income-tax-refund-india.com",
    "aadhaar-update-online.in",
    "pm-kisan-samman.in",
    "covid-relief-fund-india.com",
    "ration-card-apply-online.in",
    "fastcashloan.in",
    "easyrupee.xyz",
    "instantloan24.in",
}

# Malicious IPs observed in Indian banking trojan campaigns
MALICIOUS_IPS = {
    "185.220.101.47",
    "45.142.212.100",
    "91.108.4.0",
    "91.108.56.0",
    "198.199.98.197",
    "134.209.155.118",
    "159.89.32.157",
}

# Patterns indicating UPI fraud / fake bank
UPI_FRAUD_STRINGS = [
    r"upi.*helpline",
    r"npci.*support",
    r"kyc.*update.*bank",
    r"bank.*account.*blocked",
    r"aadhaar.*link.*account",
    r"income.?tax.*refund",
    r"pm.kisan",
    r"loan.*instant.*approve",
]


def analyze(apk_path: str, manifest_data: dict, string_data: dict) -> dict:
    """Cross-reference extracted data against Indian IOC databases."""
    result = {
        "is_fake_upi": False,
        "is_fake_bank": False,
        "is_loan_scam": False,
        "matched_packages": [],
        "matched_domains": [],
        "matched_ips": [],
        "risk_flags": [],
    }

    # Check package name
    pkg = manifest_data.get("package_name", "")
    if pkg in FAKE_PACKAGES:
        result["matched_packages"].append(pkg)
        result["is_fake_upi"] = True
        result["risk_flags"].append(f"Package '{pkg}' is in known fake-UPI blacklist")

    # Loan scam package pattern
    loan_keywords = ["loan", "rupee", "cash", "instant", "quick"]
    if any(kw in pkg.lower() for kw in loan_keywords):
        result["is_loan_scam"] = True
        result["risk_flags"].append(f"Package name '{pkg}' matches loan-scam naming pattern")

    # Check URLs for fraudulent domains
    for url_item in string_data.get("urls", []):
        url = url_item.get("value", "")
        for domain in FRAUDULENT_DOMAINS:
            if domain in url:
                result["matched_domains"].append(domain)
                result["risk_flags"].append(f"Communicates with known fraud domain: {domain}")
                result["is_fake_bank"] = True

    # Check IPs
    for ip_item in string_data.get("ips", []):
        ip = ip_item.get("value", "")
        if ip in MALICIOUS_IPS:
            result["matched_ips"].append(ip)
            result["risk_flags"].append(f"Connects to known malicious IP: {ip}")

    # Check suspicious strings for UPI fraud patterns
    all_susp = string_data.get("suspicious_strings", [])
    all_urls = string_data.get("urls", [])
    all_text = " ".join([s.get("value", "") for s in all_susp + all_urls]).lower()
    for pattern in UPI_FRAUD_STRINGS:
        if re.search(pattern, all_text, re.IGNORECASE):
            result["is_fake_upi"] = True
            result["risk_flags"].append(f"String pattern matches UPI/banking fraud: '{pattern}'")
            break

    # Deduplicate
    result["matched_domains"] = list(set(result["matched_domains"]))
    result["matched_ips"] = list(set(result["matched_ips"]))
    result["matched_packages"] = list(set(result["matched_packages"]))
    result["risk_flags"] = list(dict.fromkeys(result["risk_flags"]))

    return result
