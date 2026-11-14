"""
VerityOS AI Agents and Orchestration Module
===========================================
Member 1 ownership:
- mocks.py: Deterministic test corpora for supported, contradicted, empty, tampered scenarios.
- research_agent.py (Pending Step 5)
- data_agent.py (Pending Step 6)
- verification_agent.py (Pending Step 7)
- trust_engine_mock.py (Pending Step 4)
- orchestrator.py (Pending Step 8)
"""

from agents.data_agent import (
    run_data_agent,
)
from agents.mocks import (
    AVAILABLE_MOCK_SCENARIOS,
    compute_sha256,
    get_expected_claims,
    get_expected_verification_results,
    get_mock_evidence,
    get_mock_scenario_data,
    verify_evidence_integrity,
)
from agents.orchestrator import (
    execute_pipeline,
)
from agents.research_agent import (
    run_research_agent,
)
from agents.trust_engine_mock import (
    evaluate_trust_engine_mock,
)
from agents.verification_agent import (
    run_verification_agent,
)

__all__ = [
    "AVAILABLE_MOCK_SCENARIOS",
    "compute_sha256",
    "verify_evidence_integrity",
    "get_mock_evidence",
    "get_expected_claims",
    "get_expected_verification_results",
    "get_mock_scenario_data",
    "run_research_agent",
    "run_data_agent",
    "run_verification_agent",
    "evaluate_trust_engine_mock",
    "execute_pipeline",
]
