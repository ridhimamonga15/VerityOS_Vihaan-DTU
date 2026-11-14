"""
Pipeline bridge — Member 3.

Handles importing Member 1's execute_pipeline() or falling back to a
built-in mock.  The mock returns a valid response shape so the backend
and frontend can be developed before Member 1's code is ready.

IMPORTANT: the mock is clearly labelled — mock_mode is True and all
data is synthetic.  Never present mock output as live research.
"""

from __future__ import annotations

import uuid
import logging
from datetime import datetime, timezone
from typing import Any

from backend import config

logger = logging.getLogger(__name__)


# ------------------------------------------------------------------
# Mock pipeline — used when USE_MOCK_PIPELINE=true or when the real
# agents module is not yet available.
# ------------------------------------------------------------------

def _mock_execute_pipeline(
    query: str,
    task_id: str,
    options: dict | None = None,
) -> dict[str, Any]:
    """
    Return a deterministic mock pipeline result that matches the agreed
    response schema.  All data is synthetic and labelled as mock.
    """
    now = datetime.now(timezone.utc).isoformat()

    return {
        "task_id": task_id,
        "status": "SUCCESS",
        "query": query,
        "decision": "APPROVED",
        "trust_score": 72.5,
        "trust_grade": "B",
        "claims": [
            {
                "claim_id": "C1",
                "claim_text": "Company X reported revenue of INR 50 crore for FY2025.",
                "evidence_ids": ["E1", "E2"],
                "verification_status": "SUPPORTED",
                "supporting_evidence_ids": ["E1"],
                "contradicting_evidence_ids": [],
                "explanation": "Two independent sources confirm this figure.",
            },
            {
                "claim_id": "C2",
                "claim_text": "Company X was founded in 2010.",
                "evidence_ids": ["E1"],
                "verification_status": "SUPPORTED",
                "supporting_evidence_ids": ["E1"],
                "contradicting_evidence_ids": [],
                "explanation": "Source E1 states founding year as 2010.",
            },
            {
                "claim_id": "C3",
                "claim_text": "Company X has 5000 employees worldwide.",
                "evidence_ids": ["E2", "E3"],
                "verification_status": "CONTRADICTED",
                "supporting_evidence_ids": ["E2"],
                "contradicting_evidence_ids": ["E3"],
                "explanation": (
                    "E2 reports 5000 employees; E3 reports 3200. "
                    "Possible difference in reporting period or scope."
                ),
            },
        ],
        "evidence": [
            {
                "evidence_id": "E1",
                "source_url": "https://example.org/company-x-annual-report",
                "source_title": "Company X Annual Report FY2025",
                "snippet": "Revenue for FY2025 was INR 50 crore. Founded in 2010.",
                "source_type": "website",
                "published_at": "2026-04-15",
                "retrieved_at": now,
            },
            {
                "evidence_id": "E2",
                "source_url": "https://example.org/market-analysis",
                "source_title": "Market Analysis Report Q3 2026",
                "snippet": "Company X, with approximately 5000 employees, reported revenue of INR 50 crore.",
                "source_type": "website",
                "published_at": "2026-09-01",
                "retrieved_at": now,
            },
            {
                "evidence_id": "E3",
                "source_url": "https://example.org/company-x-profile",
                "source_title": "Company X Corporate Profile (outdated)",
                "snippet": "As of 2024, Company X has 3200 employees.",
                "source_type": "website",
                "published_at": "2024-06-01",
                "retrieved_at": now,
            },
        ],
        "verification_results": [
            {
                "claim_id": "C1",
                "status": "SUPPORTED",
                "supporting_evidence_ids": ["E1", "E2"],
                "contradicting_evidence_ids": [],
                "explanation": "Both E1 and E2 independently confirm revenue of INR 50 crore for FY2025.",
            },
            {
                "claim_id": "C2",
                "status": "SUPPORTED",
                "supporting_evidence_ids": ["E1"],
                "contradicting_evidence_ids": [],
                "explanation": "E1 states founding year as 2010.",
            },
            {
                "claim_id": "C3",
                "status": "CONTRADICTED",
                "supporting_evidence_ids": ["E2"],
                "contradicting_evidence_ids": ["E3"],
                "explanation": (
                    "E2 says 5000 employees (2026); E3 says 3200 employees (2024). "
                    "Possible growth or different reporting scope."
                ),
            },
        ],
        "trust_evaluation": {
            "overall_score": 72.5,
            "grade": "B",
            "policy_decision": "PASS",
            "dimension_scores": {
                "source_quality": 80.0,
                "evidence_support": 75.0,
                "freshness": 65.0,
                "corroboration": 70.0,
                "consistency": 60.0,
                "data_quality": 85.0,
            },
            "per_claim_evaluations": [
                {"claim_id": "C1", "score": 88.0, "decision": "PASS"},
                {"claim_id": "C2", "score": 75.0, "decision": "PASS"},
                {"claim_id": "C3", "score": 45.0, "decision": "REVIEW"},
            ],
        },
        "provenance": {
            "pipeline_stages": ["research", "data", "verification", "trust"],
            "timestamps": {
                "pipeline_start": now,
                "research_complete": now,
                "data_complete": now,
                "verification_complete": now,
                "trust_complete": now,
                "pipeline_end": now,
            },
            "mock_mode": True,
        },
        "limitations": [
            "MOCK MODE — all data is synthetic. Do not treat as live research.",
            "Evidence source E3 is from 2024 and may be outdated.",
            "Employee count conflict between E2 and E3 could not be resolved.",
        ],
        "errors": [],
    }


# ------------------------------------------------------------------
# Public function used by the route handler
# ------------------------------------------------------------------

def run_pipeline(
    query: str,
    task_id: str,
    options: dict | None = None,
) -> dict[str, Any]:
    """
    Execute the analysis pipeline.

    Tries to import Member 1's ``execute_pipeline`` when
    ``USE_MOCK_PIPELINE`` is False.  Falls back to the built-in mock
    if the import fails (with a logged warning).

    Returns:
        A dict matching the agreed pipeline response schema.
    """
    if config.USE_MOCK_PIPELINE:
        logger.info("Using MOCK pipeline (USE_MOCK_PIPELINE=true)")
        return _mock_execute_pipeline(query, task_id, options)

    # --- Attempt real pipeline import ---
    try:
        from agents.orchestrator import execute_pipeline  # type: ignore[import-untyped]

        logger.info("Using REAL pipeline from agents.orchestrator")
        result = execute_pipeline(query=query, task_id=task_id, options=options)

        # Ensure the result contains at least the required top-level fields.
        if not isinstance(result, dict):
            raise TypeError(
                f"execute_pipeline returned {type(result).__name__}, expected dict"
            )
        result.setdefault("task_id", task_id)
        result.setdefault("status", "SUCCESS")
        result.setdefault("query", query)
        return result

    except ImportError:
        logger.warning(
            "agents.orchestrator not available — falling back to mock pipeline"
        )
        return _mock_execute_pipeline(query, task_id, options)
