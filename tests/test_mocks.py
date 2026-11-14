"""
Unit Tests for agents/mocks.py
===============================
Validates the four deterministic test scenarios, SHA-256 hashing,
tamper detection, and lineage invariants.
"""

import pytest

from agents.mocks import (
    AUTHENTIC_BASELINE_SNIPPET,
    AVAILABLE_MOCK_SCENARIOS,
    TAMPERED_SNIPPET,
    compute_sha256,
    get_expected_claims,
    get_expected_verification_results,
    get_mock_evidence,
    get_mock_scenario_data,
    verify_evidence_integrity,
)
from shared.schemas import ExecutionMode, VerificationStatus


def test_available_scenarios_list():
    """Ensure all four required scenarios are registered."""
    assert set(AVAILABLE_MOCK_SCENARIOS) == {"supported", "contradicted", "empty", "tampered"}


def test_compute_sha256_known_value():
    """Verify SHA-256 calculation produces mathematically correct hash."""
    # SHA-256 for "" (empty string) is standard e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
    assert compute_sha256("") == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"


def test_supported_scenario():
    """Verify the 'supported' scenario data and integrity."""
    data = get_mock_scenario_data("supported")
    evidence = data["evidence"]
    claims = data["claims"]
    verifications = data["verification_results"]

    assert len(evidence) == 3
    assert len(claims) == 1
    assert len(verifications) == 1

    # Check evidence properties & integrity
    for ev in evidence:
        assert ev.is_mock is True
        assert ev.mode == ExecutionMode.MOCK
        assert ev.source_url.startswith("https://")
        assert ev.snippet
        assert ev.content_hash == compute_sha256(ev.snippet)
        assert verify_evidence_integrity(ev) is True

    # Check claim linkage
    c1 = claims[0]
    assert c1.claim_id == "C1"
    assert c1.evidence_ids == ["E1", "E2", "E3"]
    assert c1.value == "INR 50 crore"

    # Check verification result
    v1 = verifications[0]
    assert v1.claim_id == "C1"
    assert v1.status == VerificationStatus.SUPPORTED
    assert v1.supporting_evidence_ids == ["E1", "E2", "E3"]
    assert len(v1.contradicting_evidence_ids) == 0


def test_contradicted_scenario():
    """Verify the 'contradicted' scenario data, conflict detection, and integrity."""
    data = get_mock_scenario_data("contradicted")
    evidence = data["evidence"]
    claims = data["claims"]
    verifications = data["verification_results"]

    assert len(evidence) == 2
    assert len(claims) == 1
    assert len(verifications) == 1

    # Both records individually have valid hashes (they were legitimately retrieved from sources)
    for ev in evidence:
        assert ev.is_mock is True
        assert verify_evidence_integrity(ev) is True

    # But their contents contradict each other (INR 50 crore vs INR 35 crore)
    assert "50 crore" in evidence[0].snippet
    assert "35 crore" in evidence[1].snippet

    # Verification must flag CONTRADICTED
    v1 = verifications[0]
    assert v1.claim_id == "C1"
    assert v1.status == VerificationStatus.CONTRADICTED
    assert v1.supporting_evidence_ids == ["E1"]
    assert v1.contradicting_evidence_ids == ["E2"]


def test_empty_scenario():
    """Verify the 'empty' scenario returns zero evidence and zero claims."""
    data = get_mock_scenario_data("empty")
    assert data["evidence"] == []
    assert data["claims"] == []
    assert data["verification_results"] == []

    evidence = get_mock_evidence("empty")
    assert evidence == []
    assert get_expected_claims("empty") == []
    assert get_expected_verification_results("empty") == []


def test_tampered_scenario_integrity_failure():
    """
    Verify the 'tampered' scenario detects cryptographic content hash mismatch.
    This simulates an unauthorized post-ingestion byte modification.
    """
    data = get_mock_scenario_data("tampered")
    evidence = data["evidence"]
    claims = data["claims"]
    verifications = data["verification_results"]

    assert len(evidence) == 1
    ev = evidence[0]

    assert ev.is_mock is True
    assert ev.snippet == TAMPERED_SNIPPET
    # Hash check MUST fail because snippet was modified after baseline hash creation
    assert ev.content_hash == compute_sha256(AUTHENTIC_BASELINE_SNIPPET)
    assert compute_sha256(ev.snippet) != ev.content_hash
    assert verify_evidence_integrity(ev) is False, "Tampered evidence must fail integrity check"

    # Claim and verification reflects the integrity issue
    v1 = verifications[0]
    assert v1.status == VerificationStatus.INSUFFICIENT
    assert "integrity" in v1.explanation.lower()
    assert v1.confidence_estimate == 0.0


def test_invalid_scenario_raises_error():
    """Verify passing an unknown scenario name raises a clean ValueError."""
    with pytest.raises(ValueError) as excinfo:
        get_mock_scenario_data("non_existent_scenario")
    assert "Unknown mock_scenario" in str(excinfo.value)
