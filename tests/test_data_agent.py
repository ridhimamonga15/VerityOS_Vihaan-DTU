"""
Unit Tests for agents/data_agent.py
===================================
Validates run_data_agent across supported, contradicted, empty, tampered scenarios,
lineage preservation, interoperability with Research Agent dict output, and error cases.
"""

import pytest

from agents.data_agent import run_data_agent
from agents.mocks import get_mock_evidence
from shared.schemas import (
    ClaimRecord,
    EvidenceRecord,
    ExecutionMode,
    ModuleStatus,
)


def test_data_agent_supported_scenario():
    """Verify data agent extracts claim and links all supporting evidence in supported scenario."""
    evidence = get_mock_evidence("supported")
    envelope = run_data_agent(
        task_id="task-data-01",
        evidence=evidence,
        query="Company X revenue",
        mode=ExecutionMode.MOCK,
    )

    assert envelope.status == ModuleStatus.SUCCESS
    assert envelope.agent == "data_agent"
    assert envelope.task_id == "task-data-01"
    assert envelope.mode == ExecutionMode.MOCK
    assert envelope.error is None

    claims = envelope.data.get("claims", [])
    assert len(claims) == 1

    c1 = ClaimRecord.model_validate(claims[0])
    assert c1.claim_id == "C1"
    assert set(c1.evidence_ids) == {"E1", "E2", "E3"}
    assert c1.value == "INR 50 crore"
    assert c1.time_period == "FY2025"


def test_data_agent_contradicted_scenario():
    """Verify data agent links both conflicting evidence IDs to the extracted claim."""
    evidence = get_mock_evidence("contradicted")
    envelope = run_data_agent(
        task_id="task-data-02",
        evidence=evidence,
        query="Verify conflicting revenue",
        mode=ExecutionMode.MOCK,
    )

    assert envelope.status == ModuleStatus.SUCCESS
    claims = envelope.data.get("claims", [])
    assert len(claims) == 1

    c1 = ClaimRecord.model_validate(claims[0])
    assert c1.claim_id == "C1"
    assert set(c1.evidence_ids) == {"E1", "E2"}


def test_data_agent_empty_evidence():
    """Verify data agent returns ModuleStatus.EMPTY when evidence list is empty."""
    envelope = run_data_agent(
        task_id="task-data-03",
        evidence=[],
        mode=ExecutionMode.MOCK,
    )

    assert envelope.status == ModuleStatus.EMPTY
    assert envelope.agent == "data_agent"
    assert envelope.data.get("claims") == []
    assert envelope.error is None


def test_data_agent_tampered_scenario():
    """Verify data agent extracts the altered claim and preserves evidence linkage."""
    evidence = get_mock_evidence("tampered")
    envelope = run_data_agent(
        task_id="task-data-04",
        evidence=evidence,
        mode=ExecutionMode.MOCK,
    )

    assert envelope.status == ModuleStatus.SUCCESS
    claims = envelope.data.get("claims", [])
    assert len(claims) == 1

    c1 = ClaimRecord.model_validate(claims[0])
    assert c1.claim_id == "C1"
    assert c1.evidence_ids == ["E1"]
    assert "999 crore" in c1.claim_text


def test_data_agent_custom_evidence():
    """Verify heuristic extraction works for arbitrary custom evidence records."""
    custom_ev = EvidenceRecord(
        evidence_id="E_CUSTOM_99",
        source_url="https://acme-corp.com/press",
        source_title="Acme Press Release",
        snippet="Acme Corp announced expansion into the European market in Q3 2026.",
        source_type="website",
        retrieved_at="2026-11-14T12:00:00Z",
        is_mock=True,
    )

    envelope = run_data_agent(
        task_id="task-custom",
        evidence=[custom_ev],
        mode=ExecutionMode.MOCK,
    )

    assert envelope.status == ModuleStatus.SUCCESS
    claims = envelope.data.get("claims", [])
    assert len(claims) == 1
    c = ClaimRecord.model_validate(claims[0])
    assert c.evidence_ids == ["E_CUSTOM_99"]
    assert "Acme Corp announced expansion" in c.claim_text


def test_data_agent_dict_interoperability():
    """Verify data agent accepts serialized dicts (as passed from Research Agent envelope)."""
    evidence = get_mock_evidence("supported")
    dict_evidence = [ev.model_dump() for ev in evidence]

    envelope = run_data_agent(
        task_id="task-dict-interop",
        evidence=dict_evidence,
        mode=ExecutionMode.MOCK,
    )

    assert envelope.status == ModuleStatus.SUCCESS
    claims = envelope.data.get("claims", [])
    assert len(claims) == 1


def test_data_agent_malformed_evidence_record():
    """Verify malformed evidence record returns clean ModuleStatus.ERROR."""
    malformed_evidence = [
        {"evidence_id": "E1", "missing_required_fields": True}
    ]

    envelope = run_data_agent(
        task_id="task-malformed",
        evidence=malformed_evidence,  # type: ignore
        mode=ExecutionMode.MOCK,
    )

    assert envelope.status == ModuleStatus.ERROR
    assert "Malformed evidence record" in envelope.error
    assert "Traceback" not in envelope.error


def test_data_agent_invalid_task_id():
    """Verify empty task_id returns ModuleStatus.ERROR."""
    envelope = run_data_agent(
        task_id="",
        evidence=get_mock_evidence("supported"),
    )

    assert envelope.status == ModuleStatus.ERROR
    assert "Invalid task_id" in envelope.error


def test_data_agent_invalid_evidence_type():
    """Verify passing non-dict non-EvidenceRecord returns ModuleStatus.ERROR."""
    envelope = run_data_agent(
        task_id="task-type-err",
        evidence=["invalid_string_instead_of_record"],  # type: ignore
    )

    assert envelope.status == ModuleStatus.ERROR
    assert "Invalid evidence type" in envelope.error
