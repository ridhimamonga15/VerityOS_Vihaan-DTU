"""
Unit Tests for agents/trust_engine_mock.py
===========================================
Validates evaluate_trust_engine_mock across supported, contradicted, empty,
tampered scenarios, error handling on malformed schemas, and decision enforcement.
"""

import pytest

from agents.mocks import get_mock_scenario_data
from agents.trust_engine_mock import evaluate_trust_engine_mock
from shared.schemas import (
    ExecutionMode,
    ModuleStatus,
    TrustDecision,
    VerificationPacket,
    VerificationPacketData,
    VerificationResultRecord,
    VerificationStatus,
)


def _build_packet_for_scenario(scenario_name: str, task_id: str = "task-test-01") -> VerificationPacket:
    data = get_mock_scenario_data(scenario_name)
    return VerificationPacket(
        task_id=task_id,
        status=ModuleStatus.SUCCESS,
        agent="verification_agent",
        mode=ExecutionMode.MOCK,
        data=VerificationPacketData(
            claims=data["claims"],
            evidence=data["evidence"],
            verification_results=data["verification_results"],
        ),
    )


def test_evaluate_supported_packet():
    """Verify supported packet evaluates to PASS with high scores."""
    packet = _build_packet_for_scenario("supported")
    output = evaluate_trust_engine_mock(packet)

    assert output.status == ModuleStatus.SUCCESS
    assert output.task_id == packet.task_id
    assert output.trust_assessment is not None

    assessment = output.trust_assessment
    assert assessment.decision == TrustDecision.PASS
    assert assessment.overall_score >= 80.0
    assert assessment.dimension_scores.consistency == 100.0
    assert assessment.dimension_scores.data_quality >= 90.0

    # Explicit mock disclaimer must be present
    assert any("[MOCK" in w for w in assessment.warnings)


def test_evaluate_contradicted_packet():
    """
    Verify contradicted packet strictly evaluates to REVIEW and NEVER PASS.
    Consistency dimension must be heavily penalized.
    """
    packet = _build_packet_for_scenario("contradicted")
    output = evaluate_trust_engine_mock(packet)

    assert output.status == ModuleStatus.SUCCESS
    assert output.trust_assessment is not None

    assessment = output.trust_assessment
    assert assessment.decision == TrustDecision.REVIEW
    assert assessment.decision != TrustDecision.PASS, "Contradicted packet must never return PASS"
    assert assessment.dimension_scores.consistency <= 30.0
    assert any("CONTRADICTION" in w for w in assessment.warnings)


def test_evaluate_tampered_packet():
    """
    Verify tampered packet (SHA-256 mismatch) strictly evaluates to REJECT and NEVER PASS.
    Data quality dimension must be 0.0.
    """
    packet = _build_packet_for_scenario("tampered")
    output = evaluate_trust_engine_mock(packet)

    assert output.status == ModuleStatus.SUCCESS
    assert output.trust_assessment is not None

    assessment = output.trust_assessment
    assert assessment.decision == TrustDecision.REJECT
    assert assessment.decision != TrustDecision.PASS, "Tampered packet must never return PASS"
    assert assessment.dimension_scores.data_quality == 0.0
    assert assessment.overall_score < 25.0
    assert any("integrity check failed" in r.lower() for r in assessment.reasons)
    assert any("EVIDENCE_INTEGRITY_VIOLATION" in w for w in assessment.warnings)


def test_evaluate_empty_packet():
    """Verify empty packet evaluates to REVIEW with 0 scores."""
    packet = _build_packet_for_scenario("empty")
    output = evaluate_trust_engine_mock(packet)

    assert output.status == ModuleStatus.SUCCESS
    assert output.trust_assessment is not None
    assert output.trust_assessment.decision == TrustDecision.REVIEW
    assert output.trust_assessment.overall_score == 0.0


def test_evaluate_dict_input():
    """Verify evaluate_trust_engine_mock accepts a raw dictionary conforming to schema."""
    packet = _build_packet_for_scenario("supported")
    raw_dict = packet.model_dump()
    output = evaluate_trust_engine_mock(raw_dict)

    assert output.status == ModuleStatus.SUCCESS
    assert output.trust_assessment is not None
    assert output.trust_assessment.decision == TrustDecision.PASS


def test_evaluate_malformed_packet_schema():
    """Verify malformed dictionary returns ModuleStatus.ERROR and no raw traceback."""
    malformed_dict = {
        "task_id": "bad-task",
        "data": {
            "unsupported_key": "corrupted"
        }
    }
    output = evaluate_trust_engine_mock(malformed_dict)

    assert output.status == ModuleStatus.ERROR
    assert output.task_id == "bad-task"
    assert output.trust_assessment is None
    assert output.error is not None
    assert "Traceback" not in output.error
    assert "failed validation" in output.error


def test_evaluate_invalid_type_input():
    """Verify non-dict non-packet input returns clean ERROR envelope."""
    output = evaluate_trust_engine_mock("invalid string input")  # type: ignore

    assert output.status == ModuleStatus.ERROR
    assert output.trust_assessment is None
    assert "VerificationPacket or valid dictionary" in output.error
