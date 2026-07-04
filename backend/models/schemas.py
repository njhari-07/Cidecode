"""
Pydantic schemas for CyberKavach API request/response models.
"""
from __future__ import annotations
from typing import Any, Optional
from pydantic import BaseModel, Field
from datetime import datetime
from enum import Enum


class RiskLevel(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


# ──────────────────────────────────────────────
# Sub-models
# ──────────────────────────────────────────────

class HashInfo(BaseModel):
    md5: str
    sha1: str
    sha256: str
    file_size: int


class Permission(BaseModel):
    name: str
    is_dangerous: bool
    description: str


class DangerousCombo(BaseModel):
    permissions: list[str]
    label: str
    severity: str


class ManifestResult(BaseModel):
    package_name: str
    version_name: str
    version_code: str
    min_sdk: str
    target_sdk: str
    permissions: list[Permission]
    dangerous_combos: list[DangerousCombo]
    activities: list[str]
    services: list[str]
    receivers: list[str]
    providers: list[str]


class ExtractedString(BaseModel):
    type: str   # ip, url, api_key, aadhaar, pan, base64, credential
    value: str
    risk: str   # low, medium, high


class CertificateResult(BaseModel):
    subject: str
    issuer: str
    serial_number: str
    not_before: str
    not_after: str
    is_self_signed: bool
    is_expired: bool
    sha256_fingerprint: str
    warnings: list[str]


class YaraHit(BaseModel):
    rule: str
    severity: str
    description: str
    tags: list[str]


class ObfuscationResult(BaseModel):
    score: int  # 0-100
    short_class_ratio: float
    short_method_ratio: float
    has_reflection: bool
    has_dex_classloader: bool
    has_native_libs: bool
    has_string_encryption: bool


class VirusTotalResult(BaseModel):
    found: bool
    detection_count: int
    total_engines: int
    malware_families: list[str]
    permalink: Optional[str] = None


class AbuseIPDBResult(BaseModel):
    checked_ips: list[str]
    max_confidence: int
    flagged_ips: list[dict[str, Any]]


class IndiaIOCResult(BaseModel):
    is_fake_upi: bool
    is_fake_bank: bool
    is_loan_scam: bool
    matched_packages: list[str]
    matched_domains: list[str]
    matched_ips: list[str]
    risk_flags: list[str]


class ScoreBreakdown(BaseModel):
    static_score: int
    threat_intel_score: int
    yara_score: int
    total: int


class RiskScore(BaseModel):
    score: int
    risk_level: RiskLevel
    breakdown: ScoreBreakdown


class MitreTechnique(BaseModel):
    technique_id: str
    name: str
    tactic: str
    evidence: str


# ──────────────────────────────────────────────
# Main Analysis Result
# ──────────────────────────────────────────────

class AnalysisResult(BaseModel):
    id: str
    status: str = "complete"
    created_at: str

    hashes: HashInfo
    manifest: ManifestResult
    strings: list[ExtractedString]
    certificate: CertificateResult
    yara: list[YaraHit]
    obfuscation: ObfuscationResult
    virustotal: VirusTotalResult
    abuseipdb: AbuseIPDBResult
    india_ioc: IndiaIOCResult
    risk: RiskScore
    ai_narrative: str
    mitre: list[MitreTechnique]


# ──────────────────────────────────────────────
# API Response wrappers
# ──────────────────────────────────────────────

class UploadResponse(BaseModel):
    job_id: str
    status: str
    results: AnalysisResult


class StatsResponse(BaseModel):
    total_analyzed: int
    threats_detected: int
    india_threats: int
    critical_count: int


class ErrorResponse(BaseModel):
    error: str
    detail: str
    code: int
