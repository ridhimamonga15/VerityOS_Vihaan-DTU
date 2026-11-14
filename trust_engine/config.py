"""Configuration settings for the VerityOS Trust Engine.

This module defines all scoring weights, policy thresholds, and grading criteria.
It ensures that:
1. Weights are easily configurable.
2. Weights are strictly validated to sum to 1.0.
3. Decision thresholds for governance (PASS / REVIEW / REJECT) are clearly bounded.
"""

from dataclasses import dataclass, field
from typing import Any, Dict


# ---------------------------------------------------------------------------
# Initial Trust-Scoring Weights (Agreed Illustrative Weights)
# ---------------------------------------------------------------------------
# These represent the six core trust evaluation dimensions.
# Their sum must equal exactly 1.0.
DEFAULT_WEIGHTS: Dict[str, float] = {
    "source_quality": 0.25,     # Reliability & credibility of the source
    "evidence_support": 0.20,   # Direct backing provided by evidence
    "freshness": 0.15,          # Recency and publication timeline
    "corroboration": 0.20,      # Multi-source cross-verification
    "consistency": 0.10,        # Absence of numerical/date/unit conflicts
    "data_quality": 0.10,       # Integrity, completeness, and cleanliness
}

REQUIRED_DIMENSIONS = set(DEFAULT_WEIGHTS.keys())


# ---------------------------------------------------------------------------
# Policy Decision Thresholds (Overall Trust Score [0.0 - 1.0])
# ---------------------------------------------------------------------------
# Determines the governance action:
# - PASS:   Score >= pass_min_score (high confidence; autonomous action safe)
# - REVIEW: review_min_score <= Score < pass_min_score (requires secondary review)
# - REJECT: Score < review_min_score or fatal contradiction / hash mismatch
DEFAULT_POLICY_THRESHOLDS: Dict[str, float] = {
    "pass_min_score": 0.75,
    "review_min_score": 0.45,
}


# ---------------------------------------------------------------------------
# Qualitative Trust Grades
# ---------------------------------------------------------------------------
# Maps numerical score to high-level trust levels:
# - HIGH:   Score >= 0.75
# - MEDIUM: 0.45 <= Score < 0.75
# - LOW:    Score < 0.45
DEFAULT_GRADE_THRESHOLDS: Dict[str, float] = {
    "high": 0.75,
    "medium": 0.45,
}


# ---------------------------------------------------------------------------
# Freshness Thresholds
# ---------------------------------------------------------------------------
# Maximum age (in days) before evidence is penalized for staleness
DEFAULT_MAX_FRESHNESS_DAYS: int = 365


# ---------------------------------------------------------------------------
# Validation Functions
# ---------------------------------------------------------------------------

def validate_weights(weights: Dict[str, float], tolerance: float = 1e-6) -> bool:
    """Validate that the scoring weights are valid and sum to 1.0.
    
    Args:
        weights: Dictionary mapping dimension names to weight floats.
        tolerance: Acceptable floating-point difference from 1.0.
        
    Returns:
        True if weights are valid.
        
    Raises:
        ValueError: If weights are missing dimensions, contain negative values,
                    or do not sum to 1.0.
    """
    if not isinstance(weights, dict):
        raise ValueError(f"Weights must be a dictionary, got {type(weights).__name__}.")

    # Check for missing dimensions
    missing = REQUIRED_DIMENSIONS - set(weights.keys())
    if missing:
        raise ValueError(
            f"Weights dictionary is missing required dimensions: {sorted(list(missing))}."
        )

    # Check for non-negative numbers
    for dim, weight in weights.items():
        if not isinstance(weight, (int, float)):
            raise ValueError(f"Weight for '{dim}' must be a number, got {type(weight).__name__}.")
        if weight < 0.0:
            raise ValueError(f"Weight for '{dim}' cannot be negative: {weight}.")

    # Check that sum equals 1.0 within tolerance
    total = sum(weights.values())
    if abs(total - 1.0) > tolerance:
        raise ValueError(
            f"Trust scoring weights must sum to 1.0 (got {total:.4f}). "
            f"Please adjust dimension weights."
        )

    return True


def validate_policy_thresholds(thresholds: Dict[str, float]) -> bool:
    """Validate policy decision thresholds.
    
    Args:
        thresholds: Dictionary containing 'pass_min_score' and 'review_min_score'.
        
    Returns:
        True if thresholds are valid.
        
    Raises:
        ValueError: If thresholds are invalid or out of bounds.
    """
    if "pass_min_score" not in thresholds or "review_min_score" not in thresholds:
        raise ValueError("Policy thresholds must include 'pass_min_score' and 'review_min_score'.")

    pass_score = thresholds["pass_min_score"]
    review_score = thresholds["review_min_score"]

    if not (0.0 <= review_score < pass_score <= 1.0):
        raise ValueError(
            f"Invalid policy thresholds: expected 0.0 <= review ({review_score}) "
            f"< pass ({pass_score}) <= 1.0."
        )

    return True


# Run self-validation on default configuration
validate_weights(DEFAULT_WEIGHTS)
validate_policy_thresholds(DEFAULT_POLICY_THRESHOLDS)


# ---------------------------------------------------------------------------
# Trust Engine Configuration Container
# ---------------------------------------------------------------------------

@dataclass
class TrustEngineConfig:
    """Convenient, validated configuration object for the Trust Engine.
    
    Allows creating customized configurations while automatically validating
    weights and policy thresholds.
    """
    weights: Dict[str, float] = field(default_factory=lambda: DEFAULT_WEIGHTS.copy())
    policy_thresholds: Dict[str, float] = field(default_factory=lambda: DEFAULT_POLICY_THRESHOLDS.copy())
    grade_thresholds: Dict[str, float] = field(default_factory=lambda: DEFAULT_GRADE_THRESHOLDS.copy())
    max_freshness_days: int = DEFAULT_MAX_FRESHNESS_DAYS

    def __post_init__(self):
        """Validate configuration parameters upon instantiation."""
        validate_weights(self.weights)
        validate_policy_thresholds(self.policy_thresholds)
