"""Main Engine Coordinator for VerityOS Trust Engine (Compatibility Module).

This module re-exports the main `TrustEngineCoordinator` and `evaluate_trust_engine`
entrypoint from `trust_engine.trust_engine`, preserving compatibility with both
naming conventions (`engine.py` and `trust_engine.py`).
"""

from typing import Any, Dict

from trust_engine.trust_engine import (
    TrustEngineCoordinator,
    evaluate_trust_engine,
)

# Compatibility alias for earlier scaffolding references
TrustEngine = TrustEngineCoordinator

__all__ = ["TrustEngine", "TrustEngineCoordinator", "evaluate_trust_engine"]
