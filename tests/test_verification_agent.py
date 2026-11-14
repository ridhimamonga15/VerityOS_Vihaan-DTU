"""
Unit Tests for agents/verification_agent.py
============================================
Validates run_verification_agent across supported, contradicted, empty, tampered scenarios,
missing evidence references, SHA-256 integrity detection, and error handling.
"""

import pytest

from agents.mocks import get_mock_scenario_data
from agents.verification_agent import run_verification_agent
from shared.schemas import (
    ClaimRecord,
    EvidenceRecord,
    ExecutionMode,
    ModuleStatus,
    VerificationResultRecord,
    VerificationStatus,
)


def test_verification_agent_supported_scenario():
    """Verify supported scenario returns SUPPORTED with all 3 corroborating evidence IDs."""
    data = get_mock_scenario_data("supported")
    envelope = run_verification_agent(
        task_id="task-ver-01",
        claims=data["claims"],
        evidence=data["evidence"],
        mode=ExecutionMode.MOCK,
    )

    assert envelope.status == ModuleStatus.SUCCESS
    assert envelope.agent == "verification_agent"
    assert envelope.task_id == "task-ver-01"
    assert envelope.mode == ExecutionMode.MOCK
    assert envelope.error is None

    results = envelope.data.get("verification_results", [])
    assert len(results) == 1

    vr = VerificationResultRecord.model_validate(results[0])
    assert vr.claim_id == "C1"
    assert vr.status == VerificationStatus.SUPPORTED
    assert set(vr.supporting_evidence_ids) == {"E1", "E2", "E3"}
    assert len(vr.contradicting_evidence_ids) == 0
    assert vr.confidence_estimate >= 0.90
    assert "corroborated" in vr.explanation.lower()


def test_verification_agent_contradicted_scenario():
    """
    Verify contradicted scenario flags CONTRADICTED and NEVER SUPPORTED.
    Must correctly separate supporting (E1) and contradicting (E2) IDs.
    """
    data = get_mock_scenario_data("contradicted")
    envelope = run_verification_agent(
        task_id="task-ver-02",
        claims=data["claims"],
        evidence=data["evidence"],
        mode=ExecutionMode.MOCK,
    )

    assert envelope.status == ModuleStatus.SUCCESS
    results = envelope.data.get("verification_results", [])
    assert len(results) == 1

    vr = VerificationResultRecord.model_validate(results[0])
    assert vr.claim_id == "C1"
    assert vr.status == VerificationStatus.CONTRADICTED
    assert vr.status != VerificationStatus.SUPPORTED, "Conflicted claim must NEVER be marked SUPPORTED"
    assert vr.supporting_evidence_ids == ["E1"]
    assert vr.contradicting_evidence_ids == ["E2"]
    assert "contradiction detected" in vr.explanation.lower()


def test_verification_agent_tampered_scenario():
    """
    Verify tampered scenario (SHA-256 mismatch) flags evidence as untrustworthy
    and NEVER marks the claim as SUPPORTED.
    """
    data = get_mock_scenario_data("tampered")
    envelope = run_verification_agent(
        task_id="task-ver-03",
        claims=data["claims"],
        evidence=data["evidence"],
        mode=ExecutionMode.MOCK,
    )

    assert envelope.status == ModuleStatus.SUCCESS
    results = envelope.data.get("verification_results", [])
    assert len(results) == 1

    vr = VerificationResultRecord.model_validate(results[0])
    assert vr.claim_id == "C1"
    assert vr.status == VerificationStatus.INSUFFICIENT
    assert vr.status != VerificationStatus.SUPPORTED, "Tampered evidence claim must NEVER be SUPPORTED"
    assert "E1" in vr.contradicting_evidence_ids
    assert "cryptographic integrity verification failed" in vr.explanation.lower()


def test_verification_agent_empty_claims():
    """Verify empty claims list returns ModuleStatus.EMPTY."""
    envelope = run_verification_agent(
        task_id="task-ver-04",
        claims=[],
        evidence=[],
        mode=ExecutionMode.MOCK,
    )

    assert envelope.status == ModuleStatus.EMPTY
    assert envelope.data.get("verification_results") == []
    assert envelope.error is None


def test_verification_agent_missing_evidence_reference():
    """
    Verify that a claim referencing non-existent evidence IDs is marked INSUFFICIENT
    and NEVER marked SUPPORTED.
    """
    unbacked_claim = ClaimRecord(
        claim_id="C_UNBACKED",
        claim_text="Company X reported revenue of INR 100 crore.",
        evidence_ids=["E_NON_EXISTENT_99"],
    )

    envelope = run_verification_agent(
        task_id="task-ver-missing",
        claims=[unbacked_claim],
        evidence=[],  # No evidence provided to resolve E_NON_EXISTENT_99
        mode=ExecutionMode.MOCK,
    )

    assert envelope.status == ModuleStatus.SUCCESS
    results = envelope.data.get("verification_results", [])
    assert len(results) == 1

    vr = VerificationResultRecord.model_validate(results[0])
    assert vr.status == VerificationStatus.INSUFFICIENT
    assert vr.status != VerificationStatus.SUPPORTED
    assert "missing evidence" in vr.explanation.lower()


def test_verification_agent_dict_interoperability():
    """Verify verification agent accepts raw serialized dicts from upstream envelopes."""
    data = get_mock_scenario_data("supported")
    dict_claims = [c.model_dump() for c in data["claims"]]
    dict_evidence = [e.model_dump() for e in data["evidence"]]

    envelope = run_verification_agent(
        task_id="task-dict-interop",
        claims=dict_claims,
        evidence=dict_evidence,
        mode=ExecutionMode.MOCK,
    )

    assert envelope.status == ModuleStatus.SUCCESS
    results = envelope.data.get("verification_results", [])
    assert len(results) == 1
    assert results[0]["status"] == "SUPPORTED"


def test_verification_agent_malformed_claim():
    """Verify malformed claim dictionary returns clean ModuleStatus.ERROR."""
    malformed_claims = [{"bad_field": 123}]

    envelope = run_verification_agent(
        task_id="task-bad-claim",
        claims=malformed_claims,  # type: ignore
        evidence=[],
    )

    assert envelope.status == ModuleStatus.ERROR
    assert "Malformed claim" in envelope.error
    assert "Traceback" not in envelope.error


def test_verification_agent_malformed_evidence():
    """Verify malformed evidence dictionary returns clean ModuleStatus.ERROR."""
    data = get_mock_scenario_data("supported")
    malformed_evidence = [{"evidence_id": "E1", "missing_fields": True}]

    envelope = run_verification_agent(
        task_id="task-bad-ev",
        claims=data["claims"],
        evidence=malformed_evidence,  # type: ignore
    )

    assert envelope.status == ModuleStatus.ERROR
    assert "Malformed evidence record" in envelope.error
    assert "Traceback" not in envelope.error


def test_verification_agent_invalid_task_id():
    """Verify empty task_id returns clean ModuleStatus.ERROR."""
    data = get_mock_scenario_data("supported")
    envelope = run_verification_agent(
        task_id="",
        claims=data["claims"],
        evidence=data["evidence"],
    )

    assert envelope.status == ModuleStatus.ERROR
    assert "Invalid task_id" in envelope.error
