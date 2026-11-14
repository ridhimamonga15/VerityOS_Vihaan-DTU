"""
Unit Tests for agents/research_agent.py
=======================================
Validates run_research_agent across MOCK mode (supported, contradicted, empty, tampered),
LIVE mode (safe handling when unconfigured), empty query, and invalid inputs.
"""

import os
import pytest

from agents.mocks import compute_sha256
from agents.research_agent import run_research_agent
from shared.schemas import (
    EvidenceRecord,
    ExecutionMode,
    ModuleStatus,
)


def test_research_agent_mock_supported():
    """Verify research agent in mock mode with 'supported' scenario."""
    envelope = run_research_agent(
        task_id="task-mock-01",
        query="Research Company X revenue for FY2025",
        mode=ExecutionMode.MOCK,
        mock_scenario="supported",
    )

    assert envelope.status == ModuleStatus.SUCCESS
    assert envelope.agent == "research_agent"
    assert envelope.task_id == "task-mock-01"
    assert envelope.mode == ExecutionMode.MOCK
    assert envelope.error is None

    evidence = envelope.data.get("evidence", [])
    assert len(evidence) == 3

    for ev_dict in evidence:
        ev = EvidenceRecord.model_validate(ev_dict)
        assert ev.is_mock is True
        assert ev.mode == ExecutionMode.MOCK
        assert ev.evidence_id in ["E1", "E2", "E3"]
        assert ev.source_url.startswith("https://")
        assert ev.source_title
        assert ev.snippet
        assert ev.content_hash == compute_sha256(ev.snippet)


def test_research_agent_mock_contradicted():
    """Verify research agent in mock mode with 'contradicted' scenario."""
    envelope = run_research_agent(
        task_id="task-mock-02",
        query="Investigate conflicting revenue reports",
        mode=ExecutionMode.MOCK,
        mock_scenario="contradicted",
    )

    assert envelope.status == ModuleStatus.SUCCESS
    assert envelope.agent == "research_agent"
    evidence = envelope.data.get("evidence", [])
    assert len(evidence) == 2

    # Verify both records are marked mock
    for ev in evidence:
        assert ev["is_mock"] is True


def test_research_agent_mock_empty():
    """Verify research agent returns EMPTY status on empty scenario."""
    envelope = run_research_agent(
        task_id="task-mock-03",
        query="Non-existent entity query",
        mode=ExecutionMode.MOCK,
        mock_scenario="empty",
    )

    assert envelope.status == ModuleStatus.EMPTY
    assert envelope.agent == "research_agent"
    assert envelope.data.get("evidence") == []
    assert envelope.error is None


def test_research_agent_mock_tampered():
    """Verify research agent preserves tampered evidence and its stored hash."""
    envelope = run_research_agent(
        task_id="task-mock-04",
        query="Check filing integrity",
        mode=ExecutionMode.MOCK,
        mock_scenario="tampered",
    )

    assert envelope.status == ModuleStatus.SUCCESS
    evidence = envelope.data.get("evidence", [])
    assert len(evidence) == 1
    ev = EvidenceRecord.model_validate(evidence[0])
    assert ev.is_mock is True
    # The snippet was tampered, so it does not match content_hash
    assert compute_sha256(ev.snippet) != ev.content_hash


def test_research_agent_live_mode_unconfigured(monkeypatch):
    """
    Verify LIVE mode does NOT silently return mock data or fabricate results.
    When RESEARCH_API_KEY is not configured, it returns an explicit ERROR envelope.
    """
    monkeypatch.delenv("RESEARCH_API_KEY", raising=False)

    envelope = run_research_agent(
        task_id="task-live-01",
        query="Live market query",
        mode=ExecutionMode.LIVE,
    )

    assert envelope.status == ModuleStatus.ERROR
    assert envelope.mode == ExecutionMode.LIVE
    assert envelope.data.get("evidence") == []
    assert envelope.error is not None
    assert "Live research is not configured" in envelope.error
    assert "Traceback" not in envelope.error


def test_research_agent_empty_query():
    """Verify empty query returns ModuleStatus.EMPTY."""
    envelope = run_research_agent(
        task_id="task-empty-01",
        query="   ",
        mode=ExecutionMode.MOCK,
    )

    assert envelope.status == ModuleStatus.EMPTY
    assert envelope.data.get("evidence") == []
    assert envelope.error == "Query is empty."


def test_research_agent_invalid_task_id():
    """Verify empty or invalid task_id returns ModuleStatus.ERROR."""
    envelope = run_research_agent(
        task_id="",
        query="Some query",
        mode=ExecutionMode.MOCK,
    )

    assert envelope.status == ModuleStatus.ERROR
    assert "Invalid task_id" in envelope.error


def test_research_agent_invalid_mock_scenario():
    """Verify passing unknown scenario name returns clean ERROR envelope."""
    envelope = run_research_agent(
        task_id="task-bad-scenario",
        query="Some query",
        mode=ExecutionMode.MOCK,
        mock_scenario="unsupported_scenario_xyz",
    )

    assert envelope.status == ModuleStatus.ERROR
    assert "Invalid mock_scenario" in envelope.error
    assert "Must be one of" in envelope.error
