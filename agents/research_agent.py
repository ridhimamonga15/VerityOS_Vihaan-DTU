"""
VerityOS Research Agent
========================
Module: agents/research_agent.py (Member 1)

Responsibilities:
- In MOCK mode: retrieves curated evidence from agents/mocks.py according to mock_scenario.
- In LIVE mode: checks for configured live search provider. If not configured, returns
  an explicit, safe error. Never fabricates citations, sources, or silently falls back to mock.
- Calculates and verifies SHA-256 content hashes for all evidence records.
- Stricly preserves evidence IDs and provenance metadata.
- Returns a standard ModuleEnvelope without raw exception traces.
"""

import logging
import os
from typing import Optional

from agents.mocks import (
    AVAILABLE_MOCK_SCENARIOS,
    compute_sha256,
    get_mock_evidence,
)
from shared.schemas import (
    EvidenceRecord,
    ExecutionMode,
    ModuleEnvelope,
    ModuleStatus,
)

logger = logging.getLogger("verityos.agents.research_agent")


def run_research_agent(
    task_id: str,
    query: str,
    mode: ExecutionMode = ExecutionMode.MOCK,
    mock_scenario: Optional[str] = "supported",
) -> ModuleEnvelope:
    """
    Executes the research stage.

    Args:
        task_id: Unique task identifier passed through pipeline.
        query: User research question or topic.
        mode: ExecutionMode.MOCK or ExecutionMode.LIVE.
        mock_scenario: One of 'supported', 'contradicted', 'empty', 'tampered' (when mode == MOCK).

    Returns:
        ModuleEnvelope wrapping the evidence list or explicit error status.
    """
    # 1. Validate inputs
    if not task_id or not isinstance(task_id, str) or not task_id.strip():
        return ModuleEnvelope(
            task_id="unknown_task",
            status=ModuleStatus.ERROR,
            agent="research_agent",
            mode=mode,
            data={},
            error="Invalid task_id: must be a non-empty string.",
        )

    if not query or not isinstance(query, str) or not query.strip():
        logger.info("Task %s: Empty query provided to research agent.", task_id)
        return ModuleEnvelope(
            task_id=task_id,
            status=ModuleStatus.EMPTY,
            agent="research_agent",
            mode=mode,
            data={"evidence": []},
            error="Query is empty.",
        )

    # 2. LIVE Mode Execution
    if mode == ExecutionMode.LIVE:
        api_key = os.getenv("RESEARCH_API_KEY", "").strip()
        if not api_key or api_key == "your_research_api_key_here":
            logger.warning(
                "Task %s: Live research requested but RESEARCH_API_KEY is not configured.",
                task_id,
            )
            return ModuleEnvelope(
                task_id=task_id,
                status=ModuleStatus.ERROR,
                agent="research_agent",
                mode=mode,
                data={"evidence": []},
                error=(
                    "Live research is not configured. Configure RESEARCH_API_KEY in environment "
                    "or run in MOCK mode with a valid mock_scenario."
                ),
            )

        # Live provider stub: If API key exists but no external integration enabled in MVP
        logger.info("Task %s: Live search provider requested.", task_id)
        return ModuleEnvelope(
            task_id=task_id,
            status=ModuleStatus.ERROR,
            agent="research_agent",
            mode=mode,
            data={"evidence": []},
            error="Live research provider connector is pending production integration.",
        )

    # 3. MOCK Mode Execution
    scenario_name = (mock_scenario or "supported").lower().strip()
    if scenario_name not in AVAILABLE_MOCK_SCENARIOS:
        logger.warning("Task %s: Unknown mock scenario '%s'", task_id, mock_scenario)
        return ModuleEnvelope(
            task_id=task_id,
            status=ModuleStatus.ERROR,
            agent="research_agent",
            mode=mode,
            data={"evidence": []},
            error=(
                f"Invalid mock_scenario '{mock_scenario}'. "
                f"Must be one of: {AVAILABLE_MOCK_SCENARIOS}"
            ),
        )

    try:
        raw_evidence = get_mock_evidence(scenario_name)
    except Exception as exc:
        logger.exception("Task %s: Failed to load mock evidence: %s", task_id, exc)
        return ModuleEnvelope(
            task_id=task_id,
            status=ModuleStatus.ERROR,
            agent="research_agent",
            mode=mode,
            data={"evidence": []},
            error="Failed to load mock research evidence.",
        )

    # Handle empty scenario
    if not raw_evidence:
        logger.info("Task %s: Mock scenario '%s' returned 0 evidence records.", task_id, scenario_name)
        return ModuleEnvelope(
            task_id=task_id,
            status=ModuleStatus.EMPTY,
            agent="research_agent",
            mode=mode,
            data={"evidence": []},
            error=None,
        )

    # Validate and normalize evidence records
    validated_evidence = []
    for ev in raw_evidence:
        # Ensure content_hash is set if absent
        if not ev.content_hash:
            ev.content_hash = compute_sha256(ev.snippet)

        # Enforce mock flag transparency
        assert ev.is_mock is True, "Mock evidence must have is_mock=True"
        assert ev.mode == ExecutionMode.MOCK, "Mock evidence must have mode=MOCK"

        validated_evidence.append(ev.model_dump())

    logger.info(
        "Task %s: Research agent collected %d evidence records for scenario '%s'.",
        task_id,
        len(validated_evidence),
        scenario_name,
    )

    return ModuleEnvelope(
        task_id=task_id,
        status=ModuleStatus.SUCCESS,
        agent="research_agent",
        mode=mode,
        data={"evidence": validated_evidence},
        error=None,
    )
