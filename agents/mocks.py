"""
VerityOS Mock Scenarios & Deterministic Test Corpora
=====================================================
Module: agents/mocks.py (Member 1)

This module provides predefined, deterministic test datasets for 4 scenarios:
1. supported:
   - Multiple credible, independent sources corroborate Company X FY2025 revenue at INR 50 crore.
   - Evidence records have verified SHA-256 content hashes.
   - Downstream verification expects: SUPPORTED.
2. contradicted:
   - Two sources present conflicting numbers for Company X FY2025 revenue (INR 50 crore vs. INR 35 crore).
   - Evidence records have verified SHA-256 content hashes.
   - Downstream verification expects: CONTRADICTED.
3. empty:
   - Query yields zero relevant evidence records.
   - Downstream pipeline halts at Data/Orchestrator stage with INSUFFICIENT_DATA.
4. tampered:
   - An evidence record whose snippet has been altered after baseline hash generation.
   - SHA-256 hash check fails (integrity violation), downstream pipeline rejects or flags.

All mock data is explicitly flagged with mode=ExecutionMode.MOCK and is_mock=True.
Never represent this mock data as live research or real-world truth.
"""

import hashlib
from typing import Any, Optional

from shared.schemas import (
    ClaimRecord,
    EvidenceRecord,
    ExecutionMode,
    VerificationResultRecord,
    VerificationStatus,
)

AVAILABLE_MOCK_SCENARIOS = ["supported", "contradicted", "empty", "tampered"]

# Standard timestamps for reproducible mock data
MOCK_RETRIEVED_AT = "2026-11-14T10:00:00Z"

# Tampered scenario baselines
AUTHENTIC_BASELINE_SNIPPET = (
    "Company X reported official audited revenue of INR 50 crore for fiscal year 2025."
)
TAMPERED_SNIPPET = (
    "Company X reported official audited revenue of INR 999 crore for fiscal year 2025 [TAMPERED_MODIFIED]."
)


def compute_sha256(text: str) -> str:
    """Calculates SHA-256 hex digest of a UTF-8 string."""
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def verify_evidence_integrity(evidence: EvidenceRecord) -> bool:
    """
    Checks whether the evidence record's snippet matches its recorded content_hash.
    Returns True if intact, False if tampered or hash is missing.
    """
    if not evidence.content_hash:
        return False
    return compute_sha256(evidence.snippet) == evidence.content_hash


# ============================================================================
# Scenario 1: Supported Scenario (Multi-Source Corroboration)
# ============================================================================

def _build_supported_scenario() -> dict[str, Any]:
    s1 = "For the fiscal year ended December 31, 2025, Company X reported total annual revenue of INR 50 crore, representing a 15% increase year-over-year."
    s2 = "Audited financial statements released Monday confirm Company X achieved total revenue of INR 50 crore in FY2025, driven by strong cloud segment growth."
    s3 = "Company X's official annual report confirms the cloud infrastructure division contributed significantly to the reported INR 50 crore annual revenue in FY2025."

    evidence = [
        EvidenceRecord(
            evidence_id="E1",
            source_url="https://sec.gov/edgar/data/company-x/fy2025-10k.htm",
            source_title="Company X FY2025 Form 10-K Annual Filing",
            snippet=s1,
            source_type="filing",
            published_at="2026-01-20",
            retrieved_at=MOCK_RETRIEVED_AT,
            content_hash=compute_sha256(s1),
            mode=ExecutionMode.MOCK,
            is_mock=True,
        ),
        EvidenceRecord(
            evidence_id="E2",
            source_url="https://reuters.com/business/company-x-fy2025-earnings-report",
            source_title="Reuters Financial: Company X FY2025 Audited Earnings",
            snippet=s2,
            source_type="website",
            published_at="2026-01-22",
            retrieved_at=MOCK_RETRIEVED_AT,
            content_hash=compute_sha256(s2),
            mode=ExecutionMode.MOCK,
            is_mock=True,
        ),
        EvidenceRecord(
            evidence_id="E3",
            source_url="https://bloomberg.com/news/articles/company-x-cloud-expansion",
            source_title="Bloomberg Markets: Company X Cloud Segment Growth",
            snippet=s3,
            source_type="website",
            published_at="2026-01-25",
            retrieved_at=MOCK_RETRIEVED_AT,
            content_hash=compute_sha256(s3),
            mode=ExecutionMode.MOCK,
            is_mock=True,
        ),
    ]

    claims = [
        ClaimRecord(
            claim_id="C1",
            claim_text="Company X reported total annual revenue of INR 50 crore for FY2025.",
            evidence_ids=["E1", "E2", "E3"],
            subject="Company X",
            predicate="revenue",
            value="INR 50 crore",
            time_period="FY2025",
        )
    ]

    verification_results = [
        VerificationResultRecord(
            claim_id="C1",
            status=VerificationStatus.SUPPORTED,
            supporting_evidence_ids=["E1", "E2", "E3"],
            contradicting_evidence_ids=[],
            explanation="Claim is directly corroborated by 3 independent authoritative sources (SEC 10-K filing, Reuters, Bloomberg).",
            confidence_estimate=0.98,
        )
    ]

    return {
        "query": "Prepare a market research report on Company X FY2025 revenue.",
        "evidence": evidence,
        "claims": claims,
        "verification_results": verification_results,
    }


# ============================================================================
# Scenario 2: Contradicted Scenario (Conflicting Revenue Figures)
# ============================================================================

def _build_contradicted_scenario() -> dict[str, Any]:
    s1 = "Company X reported official audited revenue of INR 50 crore for the fiscal year 2025 in its statutory disclosures."
    s2 = "Contradicting official announcements, internal accounting drafts leaked on Tech Insider indicate Company X generated only INR 35 crore in revenue for FY2025."

    evidence = [
        EvidenceRecord(
            evidence_id="E1",
            source_url="https://sec.gov/edgar/data/company-x/fy2025-10k.htm",
            source_title="Company X FY2025 Form 10-K Annual Filing",
            snippet=s1,
            source_type="filing",
            published_at="2026-01-20",
            retrieved_at=MOCK_RETRIEVED_AT,
            content_hash=compute_sha256(s1),
            mode=ExecutionMode.MOCK,
            is_mock=True,
        ),
        EvidenceRecord(
            evidence_id="E2",
            source_url="https://unverified-tech-blog.com/leak/company-x-revenue-2025",
            source_title="Tech Insider Leak: Company X Internal Audit Concerns",
            snippet=s2,
            source_type="website",
            published_at="2026-02-01",
            retrieved_at=MOCK_RETRIEVED_AT,
            content_hash=compute_sha256(s2),
            mode=ExecutionMode.MOCK,
            is_mock=True,
        ),
    ]

    claims = [
        ClaimRecord(
            claim_id="C1",
            claim_text="Company X reported revenue of INR 50 crore for FY2025.",
            evidence_ids=["E1", "E2"],
            subject="Company X",
            predicate="revenue",
            value="INR 50 crore",
            time_period="FY2025",
        )
    ]

    verification_results = [
        VerificationResultRecord(
            claim_id="C1",
            status=VerificationStatus.CONTRADICTED,
            supporting_evidence_ids=["E1"],
            contradicting_evidence_ids=["E2"],
            explanation="Contradiction detected: Official Form 10-K (E1) states INR 50 crore, while secondary source (E2) alleges INR 35 crore for the same FY2025 period.",
            confidence_estimate=0.45,
        )
    ]

    return {
        "query": "Verify Company X FY2025 revenue figures and investigate reported inconsistencies.",
        "evidence": evidence,
        "claims": claims,
        "verification_results": verification_results,
    }


# ============================================================================
# Scenario 3: Empty Scenario (No Evidence Found)
# ============================================================================

def _build_empty_scenario() -> dict[str, Any]:
    return {
        "query": "Research financial statements and executive leadership for GhostCorp XYZ 2099.",
        "evidence": [],
        "claims": [],
        "verification_results": [],
    }


# ============================================================================
# Scenario 4: Tampered Scenario (Cryptographic Hash Mismatch)
# ============================================================================

def _build_tampered_scenario() -> dict[str, Any]:
    # Stored baseline hash was computed on authentic original text:
    stored_baseline_hash = compute_sha256(AUTHENTIC_BASELINE_SNIPPET)

    # However, the record snippet provided here has been modified post-ingestion:
    evidence = [
        EvidenceRecord(
            evidence_id="E1",
            source_url="https://sec.gov/edgar/data/company-x/fy2025-10k.htm",
            source_title="Company X FY2025 Form 10-K (Integrity Compromised)",
            snippet=TAMPERED_SNIPPET,
            source_type="filing",
            published_at="2026-01-20",
            retrieved_at=MOCK_RETRIEVED_AT,
            content_hash=stored_baseline_hash,  # Mismatch with compute_sha256(TAMPERED_SNIPPET)
            mode=ExecutionMode.MOCK,
            is_mock=True,
        )
    ]

    claims = [
        ClaimRecord(
            claim_id="C1",
            claim_text="Company X reported official audited revenue of INR 999 crore for fiscal year 2025.",
            evidence_ids=["E1"],
            subject="Company X",
            predicate="revenue",
            value="INR 999 crore",
            time_period="FY2025",
        )
    ]

    verification_results = [
        VerificationResultRecord(
            claim_id="C1",
            status=VerificationStatus.INSUFFICIENT,
            supporting_evidence_ids=[],
            contradicting_evidence_ids=["E1"],
            explanation="Cryptographic integrity verification failed: SHA-256 fingerprint of evidence E1 does not match the registered baseline hash. Content flagged as tampered.",
            confidence_estimate=0.0,
        )
    ]

    return {
        "query": "Verify authenticity and integrity of Company X filing E1.",
        "evidence": evidence,
        "claims": claims,
        "verification_results": verification_results,
    }


# ============================================================================
# Public Accessor Functions
# ============================================================================

def get_mock_scenario_data(mock_scenario: str = "supported") -> dict[str, Any]:
    """
    Returns full scenario fixture containing query, evidence, claims,
    and reference verification results for the given scenario name.
    """
    normalized = mock_scenario.lower().strip()
    if normalized == "supported":
        return _build_supported_scenario()
    elif normalized == "contradicted":
        return _build_contradicted_scenario()
    elif normalized == "empty":
        return _build_empty_scenario()
    elif normalized == "tampered":
        return _build_tampered_scenario()
    else:
        raise ValueError(
            f"Unknown mock_scenario '{mock_scenario}'. "
            f"Must be one of: {AVAILABLE_MOCK_SCENARIOS}"
        )


def get_mock_evidence(mock_scenario: str = "supported") -> list[EvidenceRecord]:
    """Returns the evidence records for the specified mock scenario."""
    return get_mock_scenario_data(mock_scenario)["evidence"]


def get_expected_claims(mock_scenario: str = "supported") -> list[ClaimRecord]:
    """Returns the expected extracted claims for the specified mock scenario."""
    return get_mock_scenario_data(mock_scenario)["claims"]


def get_expected_verification_results(mock_scenario: str = "supported") -> list[VerificationResultRecord]:
    """Returns the reference verification results for the specified mock scenario."""
    return get_mock_scenario_data(mock_scenario)["verification_results"]
