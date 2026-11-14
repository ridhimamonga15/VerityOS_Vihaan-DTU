"""Trust Scoring Engine Component for VerityOS.

This module combines the six core trust dimensions into an overall normalized
trust score strictly between 0.0 and 1.0.

Core Scoring Principles:
1. Deterministic Weighted Aggregation:
   Calculates the weighted average of available dimensions using the weights
   defined in `config.py`:
   - source_quality:     0.25
   - evidence_support:   0.20
   - freshness:          0.15
   - corroboration:      0.20
   - consistency:        0.10
   - data_quality:       0.10
   Total:                1.00

2. Explicit Unavailable Dimension Policy:
   Missing or unavailable dimensions (`score = None`) are NEVER assumed to be
   perfect (1.0) nor zero (0.0). Instead, the overall score is renormalized
   using only the available dimensions and their corresponding weights:
   Overall Score = Sum(score_i * weight_i) / Sum(weights of available dimensions)

3. Full Traceability & Coverage:
   Reports the total available weight and coverage ratio alongside the final score.
   If all dimensions are unavailable, returns `overall_trust_score = None` with
   status `INSUFFICIENT_DATA` rather than generating a misleading score.

4. Separation of Responsibilities:
   The scoring engine only combines scores supplied by responsible checkers.
   It does not perform research, semantic verification, or policy enforcement.
"""

from enum import Enum
import math
from typing import Any, Dict, List, Optional, Tuple, Union

from trust_engine.config import DEFAULT_WEIGHTS, REQUIRED_DIMENSIONS, TrustEngineConfig


# ---------------------------------------------------------------------------
# Status Enumeration
# ---------------------------------------------------------------------------

class ScoringStatus(str, Enum):
    """Execution status for the trust scoring calculation."""
    SUCCESS = "SUCCESS"                         # Score calculated successfully
    INSUFFICIENT_DATA = "INSUFFICIENT_DATA"     # No dimensions were available (all None)
    VALIDATION_ERROR = "VALIDATION_ERROR"       # Out-of-bounds, non-numeric, or invalid inputs


# ---------------------------------------------------------------------------
# Validation Function
# ---------------------------------------------------------------------------

def validate_dimension_scores(
    dimension_scores: Any,
    weights: Optional[Dict[str, float]] = None
) -> Tuple[Dict[str, Optional[float]], List[str]]:
    """Validate all supplied dimension scores against the configured schema.
    
    Checks:
    - Input must be a dictionary.
    - All dimension keys must be recognized dimensions.
    - Missing dimensions are explicitly filled with None (unavailable).
    - Available scores must be numeric, finite, and strictly in [0.0, 1.0].
    - Booleans, strings, NaN, and infinite values are rejected with clear errors.
    
    Args:
        dimension_scores: Dictionary mapping dimension names to scores or None.
        weights: Optional dictionary of recognized dimensions and weights.
        
    Returns:
        Tuple of (validated_scores_dict, validation_errors_list).
    """
    configured_weights = weights or DEFAULT_WEIGHTS
    expected_dimensions = set(configured_weights.keys())
    validated_scores: Dict[str, Optional[float]] = {}
    validation_errors: List[str] = []

    if not isinstance(dimension_scores, dict):
        return (
            {dim: None for dim in expected_dimensions},
            [f"Input dimension_scores must be a dictionary, got {type(dimension_scores).__name__}."]
        )

    # Check for unrecognized dimension names
    for dim in dimension_scores.keys():
        if dim not in expected_dimensions:
            validation_errors.append(
                f"Unrecognized dimension name: '{dim}'. "
                f"Recognized dimensions are: {sorted(list(expected_dimensions))}."
            )

    # Validate each expected dimension
    for dim in expected_dimensions:
        if dim not in dimension_scores:
            # Missing dimension is treated safely as unavailable
            validated_scores[dim] = None
            continue

        raw_val = dimension_scores[dim]

        # Unavailable dimension
        if raw_val is None:
            validated_scores[dim] = None
            continue

        # In Python, bool is a subclass of int (isinstance(True, int) == True).
        # We must explicitly reject booleans.
        if isinstance(raw_val, bool):
            validation_errors.append(
                f"Dimension '{dim}' score cannot be a boolean ({raw_val}). Expected a float/int in [0.0, 1.0]."
            )
            validated_scores[dim] = None
            continue

        # Check numeric type
        if not isinstance(raw_val, (int, float)):
            validation_errors.append(
                f"Dimension '{dim}' score must be numeric or None, got {type(raw_val).__name__}."
            )
            validated_scores[dim] = None
            continue

        # Check finite
        if math.isnan(raw_val) or math.isinf(raw_val):
            validation_errors.append(
                f"Dimension '{dim}' score must be finite, got '{raw_val}'."
            )
            validated_scores[dim] = None
            continue

        # Check range [0.0, 1.0]
        val_float = float(raw_val)
        if val_float < 0.0 or val_float > 1.0:
            validation_errors.append(
                f"Dimension '{dim}' score {raw_val} out of bounds. Must be between 0.0 and 1.0."
            )
            validated_scores[dim] = None
            continue

        validated_scores[dim] = round(val_float, 4)

    return validated_scores, validation_errors


# ---------------------------------------------------------------------------
# Coverage Calculation
# ---------------------------------------------------------------------------

def calculate_trust_coverage(
    dimension_scores: Dict[str, Optional[float]],
    weights: Optional[Dict[str, float]] = None
) -> Dict[str, Any]:
    """Calculate the weight coverage ratio represented by available dimensions.
    
    Args:
        dimension_scores: Dictionary of dimension scores.
        weights: Optional dictionary of dimension weights.
        
    Returns:
        Dictionary containing:
        - available_weight: float (sum of weights for available dimensions)
        - total_weight: float (sum of all configured weights)
        - coverage_ratio: float (available_weight / total_weight)
        - available_dimensions: List[str]
        - unavailable_dimensions: List[str]
    """
    configured_weights = weights or DEFAULT_WEIGHTS
    total_weight = round(sum(configured_weights.values()), 4)

    available_dims: List[str] = []
    unavailable_dims: List[str] = []
    available_weight = 0.0

    for dim, weight in configured_weights.items():
        score = dimension_scores.get(dim)
        if score is not None:
            available_dims.append(dim)
            available_weight += weight
        else:
            unavailable_dims.append(dim)

    available_weight = round(available_weight, 4)
    coverage_ratio = round(available_weight / total_weight, 4) if total_weight > 0 else 0.0

    return {
        "available_weight": available_weight,
        "total_weight": total_weight,
        "coverage_ratio": coverage_ratio,
        "available_dimensions": available_dims,
        "unavailable_dimensions": unavailable_dims,
    }


# ---------------------------------------------------------------------------
# Weighted Score Calculation
# ---------------------------------------------------------------------------

def calculate_weighted_score(
    dimension_scores: Dict[str, Optional[float]],
    weights: Optional[Dict[str, float]] = None
) -> Optional[float]:
    """Calculate the weighted average score across available dimensions.
    
    Formula:
    Score = Sum(score_i * weight_i) / Sum(available_weights)
    
    Renormalizes strictly among available dimensions. Excludes unavailable dimensions
    without treating them as 1.0 or 0.0.
    
    Args:
        dimension_scores: Dictionary of dimension scores (numbers or None).
        weights: Optional dictionary of dimension weights.
        
    Returns:
        Float score between 0.0 and 1.0, or None if no dimensions are available.
    """
    configured_weights = weights or DEFAULT_WEIGHTS
    available_weight_sum = 0.0
    weighted_score_sum = 0.0

    for dim, weight in configured_weights.items():
        score = dimension_scores.get(dim)
        if score is not None:
            weighted_score_sum += score * weight
            available_weight_sum += weight

    # Avoid division by zero when no dimensions are available
    if available_weight_sum <= 0.0:
        return None

    normalized_score = weighted_score_sum / available_weight_sum
    # Guard against floating-point inaccuracies
    clamped_score = max(0.0, min(1.0, normalized_score))
    return round(clamped_score, 4)


# ---------------------------------------------------------------------------
# Main Public Scoring API
# ---------------------------------------------------------------------------

def calculate_trust_score(
    dimension_scores: Any,
    config: Optional[Union[TrustEngineConfig, Dict[str, Any]]] = None
) -> Dict[str, Any]:
    """Calculate the overall trust score and produce a detailed diagnostic breakdown.
    
    Combines:
    1. Validation of dimension scores.
    2. Weight renormalization across available dimensions.
    3. Coverage calculation.
    4. Per-dimension breakdown of raw scores, weights, and contributions.
    
    Args:
        dimension_scores: Dictionary mapping dimension names to scores.
        config: Optional TrustEngineConfig instance or dictionary.
        
    Returns:
        Structured result dictionary:
        {
            "overall_trust_score": Optional[float],
            "coverage_ratio": float,
            "available_weight": float,
            "total_weight": float,
            "dimension_scores": Dict[str, Optional[float]],
            "dimension_breakdown": Dict[str, Dict[str, Any]],
            "available_dimensions": List[str],
            "unavailable_dimensions": List[str],
            "validation_errors": List[str],
            "status": str (SUCCESS, INSUFFICIENT_DATA, VALIDATION_ERROR)
        }
    """
    # Extract weights from config if provided
    weights = DEFAULT_WEIGHTS
    if isinstance(config, TrustEngineConfig):
        weights = config.weights
    elif isinstance(config, dict) and "weights" in config:
        weights = config["weights"]
    elif isinstance(config, dict) and any(k in REQUIRED_DIMENSIONS for k in config.keys()):
        weights = config

    # 1. Validate inputs
    validated_scores, validation_errors = validate_dimension_scores(dimension_scores, weights=weights)

    # 2. Calculate coverage
    coverage = calculate_trust_coverage(validated_scores, weights=weights)

    # 3. Determine status and calculate overall score
    if validation_errors:
        overall_score = None
        status = ScoringStatus.VALIDATION_ERROR.value
    elif coverage["available_weight"] <= 0.0:
        overall_score = None
        status = ScoringStatus.INSUFFICIENT_DATA.value
    else:
        overall_score = calculate_weighted_score(validated_scores, weights=weights)
        status = ScoringStatus.SUCCESS.value

    # 4. Generate dimension-level breakdown
    dimension_breakdown: Dict[str, Dict[str, Any]] = {}
    for dim, weight in weights.items():
        raw_score = validated_scores.get(dim)
        is_available = raw_score is not None

        if is_available:
            contribution = round(raw_score * weight, 4)
            explanation = (
                f"{dim}: score {raw_score:.2f} with configured weight {weight:.2f} "
                f"(raw contribution: {contribution:.4f})."
            )
        else:
            contribution = None
            explanation = (
                f"{dim}: dimension evaluated as unavailable (configured weight {weight:.2f} "
                "excluded from active weighted average)."
            )

        dimension_breakdown[dim] = {
            "weight": weight,
            "raw_score": raw_score,
            "is_available": is_available,
            "weighted_contribution": contribution,
            "explanation": explanation,
        }

    return {
        "overall_trust_score": overall_score,
        "coverage_ratio": coverage["coverage_ratio"],
        "available_weight": coverage["available_weight"],
        "total_weight": coverage["total_weight"],
        "dimension_scores": validated_scores,
        "dimension_breakdown": dimension_breakdown,
        "available_dimensions": coverage["available_dimensions"],
        "unavailable_dimensions": coverage["unavailable_dimensions"],
        "validation_errors": validation_errors,
        "status": status,
    }


# ---------------------------------------------------------------------------
# Object-Oriented Component Wrapper
# ---------------------------------------------------------------------------

class TrustScorer:
    """Computes multidimensional trust scores and normalizes them."""

    def __init__(
        self,
        weights: Optional[Dict[str, float]] = None,
        config: Optional[Union[TrustEngineConfig, Dict[str, Any]]] = None
    ):
        """Initialize TrustScorer with dimension weights.
        
        Args:
            weights: Optional dictionary overriding default weights.
            config: Optional TrustEngineConfig instance.
        """
        if weights:
            self.weights = weights.copy()
        elif isinstance(config, TrustEngineConfig):
            self.weights = config.weights.copy()
        elif isinstance(config, dict) and "weights" in config:
            self.weights = config["weights"].copy()
        else:
            self.weights = DEFAULT_WEIGHTS.copy()

    def calculate_score(self, dimension_scores: Any) -> Dict[str, Any]:
        """Calculate overall trust score and return diagnostic summary."""
        return calculate_trust_score(dimension_scores, config={"weights": self.weights})

    def score(self, dimension_scores: Any) -> Dict[str, Any]:
        """Alias for calculate_score."""
        return self.calculate_score(dimension_scores)

    def calculate_overall_score(self, dimension_scores: Dict[str, Any]) -> Optional[float]:
        """Calculate weighted aggregate score normalized between 0.0 and 1.0."""
        res = self.calculate_score(dimension_scores)
        return res["overall_trust_score"]

    def score_from_checkers(self, intermediate_results: Dict[str, Any]) -> Dict[str, Any]:
        """Calculate dimension scores from component outputs and evaluate overall trust score."""
        dims = self.calculate_dimension_scores(intermediate_results)
        return self.calculate_score(dims)

    def calculate_coverage(self, dimension_scores: Dict[str, Any]) -> Dict[str, Any]:
        """Calculate weight coverage represented by available dimensions."""
        validated, _ = validate_dimension_scores(dimension_scores, weights=self.weights)
        return calculate_trust_coverage(validated, weights=self.weights)

    def calculate_dimension_scores(
        self,
        intermediate_results: Dict[str, Any]
    ) -> Dict[str, Optional[float]]:
        """Map checker component outputs to the six core dimension scores.
        
        Args:
            intermediate_results: Dictionary containing outputs from:
                - source_checker
                - freshness_checker
                - consistency_checker
                - integrity_checker
                - verification_results (from Member 1)
                
        Returns:
            Dictionary mapping dimension names to scores or None.
        """
        dimension_scores: Dict[str, Optional[float]] = {
            dim: None for dim in self.weights.keys()
        }

        # Source Quality from SourceChecker
        if "source_quality" in intermediate_results:
            dimension_scores["source_quality"] = intermediate_results["source_quality"]
        elif "source_checker" in intermediate_results:
            sc = intermediate_results["source_checker"]
            dimension_scores["source_quality"] = sc.get("average_reliability_score")

        # Freshness from FreshnessChecker
        if "freshness" in intermediate_results:
            dimension_scores["freshness"] = intermediate_results["freshness"]
        elif "freshness_checker" in intermediate_results:
            fc = intermediate_results["freshness_checker"]
            dimension_scores["freshness"] = fc.get("average_freshness_score")

        # Consistency from ConsistencyChecker
        if "consistency" in intermediate_results:
            dimension_scores["consistency"] = intermediate_results["consistency"]
        elif "consistency_checker" in intermediate_results:
            cc = intermediate_results["consistency_checker"]
            dimension_scores["consistency"] = cc.get("average_consistency_score")

        # Data Quality from IntegrityChecker
        if "data_quality" in intermediate_results:
            dimension_scores["data_quality"] = intermediate_results["data_quality"]
        elif "integrity_checker" in intermediate_results:
            ic = intermediate_results["integrity_checker"]
            # If integrity report matches -> 1.0; modified -> 0.0; missing/unavailable -> None
            status = ic.get("integrity_status")
            if status == "INTACT":
                dimension_scores["data_quality"] = 1.0
            elif status == "MODIFIED":
                dimension_scores["data_quality"] = 0.0
            else:
                dimension_scores["data_quality"] = None

        # Evidence Support from Member 1 Verification Results
        if "evidence_support" in intermediate_results:
            dimension_scores["evidence_support"] = intermediate_results["evidence_support"]

        # Corroboration from multi-source cross-verification
        if "corroboration" in intermediate_results:
            dimension_scores["corroboration"] = intermediate_results["corroboration"]

        return dimension_scores
