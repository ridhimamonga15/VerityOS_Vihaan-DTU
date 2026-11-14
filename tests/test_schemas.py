"""
Schema Validation Tests for VerityOS Shared Contracts
======================================================
Tests validation, constraints, serialization, and invariants of shared/schemas.py.
"""

import pytest
from pydantic import ValidationError

from shared.schemas import (
    AuditStep,
    ClaimRecord,
    EvidenceRecord,
    ExecutionMode,
    FinalPipelineResponse,
    ModuleEnvelope,
    ModuleStatus,
    ProductState,
    TrustAssessmentRecord,
    TrustDecision,
    TrustDimensionScores,
    TrustEngineOutput,
    VerificationPacket,
    VerificationPacketData,
    VerificationResultRecord,
    VerificationStatus,
)


def test_enums():
    """Verify all agreed enum values and string representations."""
    assert ExecutionMode.MOCK == "mock"
    assert ExecutionMode.LIVE == "live"

    assert ModuleStatus.SUCCESS == "SUCCESS"
    assert ModuleStatus.EMPTY == "EMPTY"
    assert ModuleStatus.ERROR == "ERROR"

    assert VerificationStatus.SUPPORTED == "SUPPORTED"
    assert VerificationStatus.CONTRADICTED == "CONTRADICTED"
    assert VerificationStatus.INSUFFICIENT == "INSUFFICIENT"

    assert TrustDecision.PASS == "PASS"
    assert TrustDecision.REVIEW == "REVIEW"
    assert TrustDecision.REJECT == "REJECT"

    assert ProductState.APPROVED == "APPROVED"
    assert ProductState.QUARANTINED == "QUARANTINED"
    assert ProductState.REJECTED == "REJECTED"
    assert ProductState.INSUFFICIENT_DATA == "INSUFFICIENT_DATA"
    assert ProductState.ERROR == "ERROR"


def test_evidence_record_valid():
    """Verify valid EvidenceRecord instantiation and hashing/mock defaults."""
    ev = EvidenceRecord(
        evidence_id="E1",
        source_url="https://sec.gov/filings/company-x-2025",
        source_title="Company X 10-K FY2025",
        snippet="Company X reported total annual revenue of INR 50 crore.",
        source_type="filing",
        published_at="2026-01-15",
        retrieved_at="2026-11-14T12:00:00Z",
        content_hash="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        is_mock=True,
    )
    assert ev.evidence_id == "E1"
    assert ev.is_mock is True
    assert ev.content_hash is not None


def test_evidence_record_extra_forbid():
    """Ensure unexpected fields are rejected."""
    with pytest.raises(ValidationError):
        EvidenceRecord(
            evidence_id="E1",
            source_url="https://example.com",
            source_title="Title",
            snippet="Snippet",
            retrieved_at="2026-11-14T12:00:00Z",
            fabricated_field="illegal",  # forbidden extra
        )


def test_claim_record_requires_evidence_lineage():
    """Verify that every claim must reference at least one evidence_id."""
    # Valid claim with 1 evidence_id
    c1 = ClaimRecord(
        claim_id="C1",
        claim_text="Company X reported revenue of INR 50 crore for FY2025.",
        evidence_ids=["E1"],
        subject="Company X",
        predicate="revenue",
        value="INR 50 crore",
        time_period="FY2025",
    )
    assert c1.claim_id == "C1"
    assert len(c1.evidence_ids) == 1

    # Invalid claim with empty evidence_ids must fail validation
    with pytest.raises(ValidationError):
        ClaimRecord(
            claim_id="C2",
            claim_text="Unsupported hallucinated claim.",
            evidence_ids=[],  # empty list violates min_length=1
        )


def test_verification_result_record():
    """Verify VerificationResultRecord status, bounds, and confidence."""
    vr = VerificationResultRecord(
        claim_id="C1",
        status=VerificationStatus.SUPPORTED,
        supporting_evidence_ids=["E1"],
        contradicting_evidence_ids=[],
        explanation="Directly corroborated by audited filing E1.",
        confidence_estimate=0.95,
    )
    assert vr.status == VerificationStatus.SUPPORTED
    assert vr.confidence_estimate == 0.95

    # Out of range confidence estimate must fail
    with pytest.raises(ValidationError):
        VerificationResultRecord(
            claim_id="C1",
            status=VerificationStatus.SUPPORTED,
            explanation="Invalid confidence",
            confidence_estimate=1.5,  # exceeds 1.0
        )


def test_verification_packet_assembly():
    """Verify full VerificationPacket serialization and structure."""
    ev = EvidenceRecord(
        evidence_id="E1",
        source_url="https://example.com",
        source_title="Annual Report",
        snippet="Revenue was INR 50 crore.",
        retrieved_at="2026-11-14T12:00:00Z",
        is_mock=True,
    )
    cl = ClaimRecord(
        claim_id="C1",
        claim_text="Revenue was INR 50 crore.",
        evidence_ids=["E1"],
    )
    vr = VerificationResultRecord(
        claim_id="C1",
        status=VerificationStatus.SUPPORTED,
        supporting_evidence_ids=["E1"],
        explanation="Supported by source E1.",
    )

    packet = VerificationPacket(
        task_id="task-001",
        status=ModuleStatus.SUCCESS,
        agent="verification_agent",
        mode=ExecutionMode.MOCK,
        data=VerificationPacketData(
            claims=[cl],
            evidence=[ev],
            verification_results=[vr],
        ),
    )

    dumped = packet.model_dump()
    assert dumped["task_id"] == "task-001"
    assert dumped["data"]["claims"][0]["claim_id"] == "C1"
    assert dumped["data"]["evidence"][0]["evidence_id"] == "E1"
    assert dumped["data"]["verification_results"][0]["status"] == "SUPPORTED"


def test_trust_dimension_scores_bounds():
    """Verify 0-100 score bounds on TrustDimensionScores."""
    scores = TrustDimensionScores(
        source_quality=85.0,
        evidence_support=90.0,
        freshness=80.0,
        corroboration=75.0,
        consistency=100.0,
        data_quality=95.0,
    )
    assert not hasattr(scores, "overall_score")
    assert scores.source_quality == 85.0

    # Out-of-bounds score (< 0 or > 100) must fail
    with pytest.raises(ValidationError):
        TrustDimensionScores(
            source_quality=105.0,  # exceeds 100.0
            evidence_support=90.0,
            freshness=80.0,
            corroboration=75.0,
            consistency=100.0,
            data_quality=95.0,
        )


def test_trust_assessment_record():
    """Verify TrustAssessmentRecord and TrustEngineOutput."""
    scores = TrustDimensionScores(
        source_quality=90.0,
        evidence_support=85.0,
        freshness=80.0,
        corroboration=90.0,
        consistency=100.0,
        data_quality=95.0,
    )
    assessment = TrustAssessmentRecord(
        overall_score=89.5,
        decision=TrustDecision.PASS,
        dimension_scores=scores,
        reasons=["High corroboration across independent filings."],
        warnings=[],
        evaluated_at="2026-11-14T12:05:00Z",
    )
    output = TrustEngineOutput(
        task_id="task-001",
        status=ModuleStatus.SUCCESS,
        trust_assessment=assessment,
    )
    assert output.trust_assessment.decision == TrustDecision.PASS
    assert output.trust_assessment.overall_score == 89.5


def test_final_pipeline_response_envelope():
    """Verify FinalPipelineResponse completeness and serialization."""
    step = AuditStep(
        stage="research",
        agent="research_agent",
        status=ModuleStatus.SUCCESS,
        timestamp="2026-11-14T12:00:00Z",
        summary="Retrieved 1 source record.",
    )
    resp = FinalPipelineResponse(
        task_id="task-001",
        query="Verify Company X revenue",
        mode=ExecutionMode.MOCK,
        product_state=ProductState.APPROVED,
        trust_decision=TrustDecision.PASS,
        overall_trust_score=89.5,
        summary="Company X revenue was verified as INR 50 crore for FY2025.",
        claims=[],
        evidence=[],
        verification_results=[],
        audit_trail=[step],
        warnings=[],
        is_mock=True,
        error=None,
    )

    dumped = resp.model_dump()
    assert dumped["task_id"] == "task-001"
    assert dumped["product_state"] == "APPROVED"
    assert dumped["mode"] == "mock"
    assert dumped["is_mock"] is True
    assert dumped["error"] is None


def test_live_mode_never_labelled_as_mock():
    """
    Verify that when ExecutionMode is LIVE, is_mock is strictly False,
    and a LIVE execution is never accidentally labelled as mock by default.
    """
    # 1. EvidenceRecord with mode=LIVE without specifying is_mock
    ev_live = EvidenceRecord(
        evidence_id="E_LIVE_1",
        source_url="https://live-verified-filing.com/sec/10k",
        source_title="Live Audited Filing",
        snippet="Audited revenue verified in live production environment.",
        retrieved_at="2026-11-14T12:00:00Z",
        mode=ExecutionMode.LIVE,
    )
    assert ev_live.mode == ExecutionMode.LIVE
    assert ev_live.is_mock is False, "LIVE EvidenceRecord must never default or resolve to is_mock=True"

    # 2. EvidenceRecord with is_mock=False without specifying mode
    ev_live_explicit = EvidenceRecord(
        evidence_id="E_LIVE_2",
        source_url="https://live-verified-filing.com/sec/10k",
        source_title="Live Audited Filing 2",
        snippet="Audited revenue verified.",
        retrieved_at="2026-11-14T12:00:00Z",
        is_mock=False,
    )
    assert ev_live_explicit.mode == ExecutionMode.LIVE
    assert ev_live_explicit.is_mock is False

    # 3. FinalPipelineResponse with mode=LIVE without specifying is_mock
    resp_live = FinalPipelineResponse(
        task_id="task-live-1",
        query="Live check",
        mode=ExecutionMode.LIVE,
        product_state=ProductState.APPROVED,
        summary="Live execution result",
    )
    assert resp_live.mode == ExecutionMode.LIVE
    assert resp_live.is_mock is False, "LIVE FinalPipelineResponse must never default or resolve to is_mock=True"

    # 4. FinalPipelineResponse with is_mock=False
    resp_live_explicit = FinalPipelineResponse(
        task_id="task-live-2",
        query="Live check",
        is_mock=False,
        product_state=ProductState.APPROVED,
        summary="Live execution result",
    )
    assert resp_live_explicit.mode == ExecutionMode.LIVE
    assert resp_live_explicit.is_mock is False

