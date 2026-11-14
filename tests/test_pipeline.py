"""
End-to-End Pipeline Integration Tests
======================================
Module: tests/test_pipeline.py
Validates execute_pipeline across all 4 benchmark scenarios, fail-safe rules,
Trust Engine modes, exception handling, and decision mappings.
"""

from unittest.mock import patch
import pytest

from agents.orchestrator import execute_pipeline
from shared.schemas import (
    ExecutionMode,
    ModuleStatus,
    ProductState,
    TrustAssessmentRecord,
    TrustDecision,
    TrustDimensionScores,
    TrustEngineOutput,
    VerificationStatus,
)


def test_pipeline_supported_scenario():
    """Verify supported scenario maps cleanly to APPROVED with high trust score."""
    resp = execute_pipeline(
        task_id="task-pipe-supported",
        query="Research Company X revenue for FY2025",
        mode=ExecutionMode.MOCK,
        mock_scenario="supported",
        use_mock_trust_engine=True,
    )

    assert resp.task_id == "task-pipe-supported"
    assert resp.product_state == ProductState.APPROVED
    assert resp.trust_decision == TrustDecision.PASS
    assert resp.overall_trust_score is not None
    assert resp.overall_trust_score >= 80.0
    assert resp.is_mock is True
    assert resp.mode == ExecutionMode.MOCK
    assert resp.error is None

    # Lineage and data checks
    assert len(resp.claims) == 1
    assert len(resp.evidence) == 3
    assert len(resp.verification_results) == 1

    c1 = resp.claims[0]
    assert c1.claim_id == "C1"
    assert set(c1.evidence_ids) == {"E1", "E2", "E3"}

    v1 = resp.verification_results[0]
    assert v1.status == VerificationStatus.SUPPORTED

    # Audit trail validation
    stages = [step.stage for step in resp.audit_trail]
    assert "intake" in stages
    assert "research" in stages
    assert "data_extraction" in stages
    assert "verification" in stages
    assert "trust_engine" in stages
    assert "policy_gate" in stages


def test_pipeline_contradicted_scenario():
    """Verify contradicted scenario maps strictly to QUARANTINED (never APPROVED)."""
    resp = execute_pipeline(
        task_id="task-pipe-contradicted",
        query="Investigate conflicting revenue reports",
        mode=ExecutionMode.MOCK,
        mock_scenario="contradicted",
        use_mock_trust_engine=True,
    )

    assert resp.product_state == ProductState.QUARANTINED
    assert resp.product_state != ProductState.APPROVED, "Contradicted pipeline must never be APPROVED"
    assert resp.trust_decision == TrustDecision.REVIEW
    assert len(resp.verification_results) == 1
    assert resp.verification_results[0].status == VerificationStatus.CONTRADICTED
    assert "Quarantined for Review" in resp.summary


def test_pipeline_empty_scenario():
    """Verify empty scenario halts safely with INSUFFICIENT_DATA."""
    resp = execute_pipeline(
        task_id="task-pipe-empty",
        query="Query returning no results",
        mode=ExecutionMode.MOCK,
        mock_scenario="empty",
        use_mock_trust_engine=True,
    )

    assert resp.product_state == ProductState.INSUFFICIENT_DATA
    assert resp.product_state != ProductState.APPROVED
    assert resp.evidence == []
    assert resp.claims == []
    assert resp.trust_decision is None
    assert "zero evidence records" in resp.summary


def test_pipeline_tampered_scenario():
    """Verify tampered scenario (SHA-256 mismatch) maps strictly to REJECTED."""
    resp = execute_pipeline(
        task_id="task-pipe-tampered",
        query="Check altered document",
        mode=ExecutionMode.MOCK,
        mock_scenario="tampered",
        use_mock_trust_engine=True,
    )

    assert resp.product_state == ProductState.REJECTED
    assert resp.product_state != ProductState.APPROVED
    assert resp.trust_decision == TrustDecision.REJECT
    assert resp.overall_trust_score is not None
    assert resp.overall_trust_score < 25.0
    assert "Rejected" in resp.summary


def test_pipeline_production_trust_engine_not_installed():
    """
    Verify that requesting production Trust Engine when it is not installed
    returns a clean ERROR and NEVER silently substitutes the mock Trust Engine.
    """
    resp = execute_pipeline(
        task_id="task-pipe-prod-unavail",
        query="Valid query",
        mode=ExecutionMode.MOCK,
        mock_scenario="supported",
        use_mock_trust_engine=False,  # Request live Member 2 Trust Engine
    )

    assert resp.product_state == ProductState.ERROR
    assert "Production Trust Engine (Member 2) is not available" in resp.error
    assert resp.product_state != ProductState.APPROVED


def test_pipeline_production_trust_engine_installed():
    """
    Verify that when Member 2's production Trust Engine is present and returns a valid
    evaluation, execute_pipeline() invokes it, preserves its scores/reasons, and maps decisions.
    """
    from unittest.mock import MagicMock
    import sys

    prod_scores = TrustDimensionScores(
        source_quality=94.0,
        evidence_support=96.0,
        freshness=90.0,
        corroboration=92.0,
        consistency=100.0,
        data_quality=99.0,
    )
    prod_assessment = TrustAssessmentRecord(
        overall_score=95.2,
        decision=TrustDecision.PASS,
        dimension_scores=prod_scores,
        reasons=["Production Member 2 verification: All dimensions verified."],
        warnings=[],
        evaluated_at="2026-11-14T12:00:00Z",
    )
    prod_output = TrustEngineOutput(
        task_id="task-pipe-prod-success",
        status=ModuleStatus.SUCCESS,
        trust_assessment=prod_assessment,
    )

    mock_module = MagicMock()
    mock_module.evaluate_trust_engine = MagicMock(return_value=prod_output)

    with patch.dict(sys.modules, {"trust_engine": MagicMock(), "trust_engine.trust_engine": mock_module}):
        resp = execute_pipeline(
            task_id="task-pipe-prod-success",
            query="Company X revenue",
            mode=ExecutionMode.MOCK,
            mock_scenario="supported",
            use_mock_trust_engine=False,  # Call production Trust Engine
        )

        assert resp.product_state == ProductState.APPROVED
        assert resp.trust_decision == TrustDecision.PASS
        assert resp.overall_trust_score == 95.2
        assert mock_module.evaluate_trust_engine.called
        te_steps = [s for s in resp.audit_trail if s.stage == "trust_engine"]
        assert len(te_steps) == 1
        assert te_steps[0].agent == "trust_engine_production"


def test_pipeline_trust_engine_exception_handling():
    """
    Verify that an unexpected exception inside the Trust Engine
    is safely caught, logged, and quarantined (NEVER APPROVED).
    """
    with patch("agents.orchestrator.evaluate_trust_engine_mock", side_effect=RuntimeError("Simulated Trust Engine crash")):
        resp = execute_pipeline(
            task_id="task-pipe-crash",
            query="Valid query",
            mock_scenario="supported",
            use_mock_trust_engine=True,
        )

        assert resp.product_state == ProductState.QUARANTINED
        assert resp.product_state != ProductState.APPROVED
        assert resp.error is not None
        assert "Traceback" not in resp.error
        assert "Trust Engine assessment was invalid" in resp.summary or "error" in resp.error.lower()


def test_pipeline_malformed_trust_engine_output():
    """
    Verify that if the Trust Engine returns an error envelope or None assessment,
    it is safely quarantined and never APPROVED.
    """
    bad_output = TrustEngineOutput(
        task_id="task-pipe-bad-out",
        status=ModuleStatus.ERROR,
        trust_assessment=None,
        error="Internal algorithm error",
    )
    with patch("agents.orchestrator.evaluate_trust_engine_mock", return_value=bad_output):
        resp = execute_pipeline(
            task_id="task-pipe-bad-out",
            query="Valid query",
            mock_scenario="supported",
            use_mock_trust_engine=True,
        )

        assert resp.product_state == ProductState.QUARANTINED
        assert resp.product_state != ProductState.APPROVED
        assert "MALFORMED_TRUST_OUTPUT" in resp.warnings[0]


def test_pipeline_contradiction_failsafe_override():
    """
    Test Orchestrator's internal fail-safe gate:
    Even if a hypothetical buggy Trust Engine returned PASS for a contradicted claim,
    the Orchestrator's policy gate must override it to QUARANTINED.
    """
    dummy_pass_assessment = TrustAssessmentRecord(
        overall_score=95.0,
        decision=TrustDecision.PASS,  # Erroneous PASS
        dimension_scores=TrustDimensionScores(
            source_quality=95.0,
            evidence_support=95.0,
            freshness=95.0,
            corroboration=95.0,
            consistency=95.0,
            data_quality=95.0,
        ),
        reasons=["Erroneous pass"],
        warnings=[],
        evaluated_at="2026-11-14T12:00:00Z",
    )
    pass_output = TrustEngineOutput(
        task_id="task-override-1",
        status=ModuleStatus.SUCCESS,
        trust_assessment=dummy_pass_assessment,
    )

    with patch("agents.orchestrator.evaluate_trust_engine_mock", return_value=pass_output):
        # We run the 'contradicted' scenario
        resp = execute_pipeline(
            task_id="task-override-1",
            query="Contradicted test",
            mock_scenario="contradicted",
            use_mock_trust_engine=True,
        )

        # Policy gate MUST have overridden PASS to QUARANTINED
        assert resp.product_state == ProductState.QUARANTINED
        assert resp.product_state != ProductState.APPROVED
        assert any("POLICY_GATE_OVERRIDE" in w for w in resp.warnings)


def test_pipeline_tamper_failsafe_override():
    """
    Test Orchestrator's internal fail-safe gate:
    Even if a hypothetical buggy Trust Engine returned PASS for tampered evidence,
    the Orchestrator's policy gate must override it to REJECTED.
    """
    dummy_pass_assessment = TrustAssessmentRecord(
        overall_score=95.0,
        decision=TrustDecision.PASS,  # Erroneous PASS
        dimension_scores=TrustDimensionScores(
            source_quality=95.0,
            evidence_support=95.0,
            freshness=95.0,
            corroboration=95.0,
            consistency=95.0,
            data_quality=95.0,
        ),
        reasons=["Erroneous pass"],
        warnings=[],
        evaluated_at="2026-11-14T12:00:00Z",
    )
    pass_output = TrustEngineOutput(
        task_id="task-override-2",
        status=ModuleStatus.SUCCESS,
        trust_assessment=dummy_pass_assessment,
    )

    with patch("agents.orchestrator.evaluate_trust_engine_mock", return_value=pass_output):
        # We run the 'tampered' scenario
        resp = execute_pipeline(
            task_id="task-override-2",
            query="Tampered test",
            mock_scenario="tampered",
            use_mock_trust_engine=True,
        )

        # Policy gate MUST have overridden PASS to REJECTED
        assert resp.product_state == ProductState.REJECTED
        assert resp.product_state != ProductState.APPROVED
        assert any("POLICY_GATE_OVERRIDE" in w for w in resp.warnings)


def test_pipeline_invalid_inputs():
    """Verify empty task_id or query are handled gracefully."""
    # Empty task_id
    resp_bad_task = execute_pipeline(task_id="", query="Some query")
    assert resp_bad_task.product_state == ProductState.ERROR
    assert "Invalid task_id" in resp_bad_task.error

    # Empty query
    resp_empty_query = execute_pipeline(task_id="task-01", query="   ")
    assert resp_empty_query.product_state == ProductState.INSUFFICIENT_DATA
    assert "No query provided" in resp_empty_query.summary
