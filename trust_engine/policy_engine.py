"""Policy Engine Component for VerityOS.

This module evaluates overall trust scores, coverage ratios, and critical evaluation
flags against governance policies to produce final actionable outcomes:
- PASS:   High confidence, trust score >= 0.75, sufficient coverage (>= 0.50),
          and zero critical evaluation flags. Safe for autonomous action.
- REVIEW: Moderate trust score (0.45 <= score < 0.75), insufficient coverage (< 0.50),
          unavailable data (None), or critical flags (e.g. hash mismatch, contradicted claims).
          Requires supervisor or secondary human review.
- REJECT: Low trust score (< 0.45). Unacceptable risk.

Core Design Principles:
1. Strict Threshold Governance:
   Directly applies thresholds defined in `config.py`:
   - PASS:   Score >= 0.75
   - REVIEW: Score >= 0.45 and < 0.75
   - REJECT: Score < 0.45

2. Separation of Trust Grade vs. Policy Decision:
   Trust Grade (HIGH, MEDIUM, LOW, UNAVAILABLE) strictly reflects numerical score.
   Policy Decision (PASS, REVIEW, REJECT) enforces safety rules and critical flags.
   For example, a score of 0.90 with INTEGRITY_MISMATCH receives:
   - Trust Grade: HIGH
   - Policy Decision: REVIEW

3. Safety First & Flag Non-Neglect:
   A critical flag forces at least REVIEW and can NEVER be overridden by a high score.
   However, flags do not automatically force REJECT unless configured or score < 0.45.

4. Coverage Enforcement:
   Trust coverage below 0.50 automatically triggers LOW_COVERAGE and prevents PASS.
   Missing dimensions generate diagnostic warnings and are neither assumed to be
   perfect (1.0) nor penalized as zero (0.0).

5. Separation of Responsibilities:
   The Policy Engine consumes scores and flags; it does not perform research,
   semantic claim verification, hashing, or orchestration retries.
"""

from enum import Enum
import math
from typing import Any, Dict, List, Optional, Tuple, Union

from trust_engine.config import (
    DEFAULT_GRADE_THRESHOLDS,
    DEFAULT_POLICY_THRESHOLDS,
    TrustEngineConfig,
)


# ---------------------------------------------------------------------------
# Enumerations
# ---------------------------------------------------------------------------

class PolicyDecision(str, Enum):
    """Actionable governance outcomes produced by the Policy Engine."""
    PASS = "PASS"       # Autonomous execution permitted
    REVIEW = "REVIEW"   # Secondary human or supervisor review required
    REJECT = "REJECT"   # Execution blocked due to low trust


class TrustGrade(str, Enum):
    """Qualitative trust grades strictly describing the numerical score."""
    HIGH = "HIGH"               # Score >= 0.75
    MEDIUM = "MEDIUM"           # 0.45 <= Score < 0.75
    LOW = "LOW"                 # Score < 0.45
    UNAVAILABLE = "UNAVAILABLE" # Score is None or uncomputable


class CriticalFlag(str, Enum):
    """Recognized critical safety flags that mandate at least REVIEW."""
    INTEGRITY_MISMATCH = "INTEGRITY_MISMATCH"       # SHA-256 hash mismatch
    CONTRADICTED_CLAIM = "CONTRADICTED_CLAIM"       # Evidence directly contradicts claim
    INCONSISTENT_DATA = "INCONSISTENT_DATA"         # Structured data conflicting across sources
    FUTURE_DATED_EVIDENCE = "FUTURE_DATED_EVIDENCE" # Invalid future publication date
    LOW_COVERAGE = "LOW_COVERAGE"                   # Evaluated coverage below minimum threshold


class PolicyStatus(str, Enum):
    """Operational status of the policy evaluation."""
    SUCCESS = "SUCCESS"                         # Evaluation completed successfully
    INSUFFICIENT_DATA = "INSUFFICIENT_DATA"     # Missing score or all dimensions unavailable
    VALIDATION_ERROR = "VALIDATION_ERROR"       # Invalid scores, out-of-bounds, or bad input


# Minimum coverage required before PASS can be considered
DEFAULT_MIN_COVERAGE: float = 0.50

# Set of recognized critical flag string values
RECOGNIZED_CRITICAL_FLAGS = {flag.value for flag in CriticalFlag}


# ---------------------------------------------------------------------------
# Decision Result Container
# ---------------------------------------------------------------------------

class PolicyDecisionResult(tuple):
    """Result tuple of (decision, explanation) with named attribute and dict-like access.
    
    Supports:
    - Unpacking: `decision, explanation = determine_policy_decision(...)`
    - Attribute access: `res.decision`, `res.policy_decision`, `res.explanation`
    - Dict-like key access: `res["decision"]`, `res["explanation"]`
    - Index access: `res[0]`, `res[1]`
    """

    def __new__(cls, decision: Union[str, PolicyDecision], explanation: str):
        dec_val = decision.value if isinstance(decision, PolicyDecision) else str(decision)
        return super().__new__(cls, (dec_val, str(explanation)))

    @property
    def decision(self) -> str:
        """The governance decision string (PASS, REVIEW, REJECT)."""
        return self[0]

    @property
    def policy_decision(self) -> str:
        """Alias for decision property."""
        return self[0]

    @property
    def explanation(self) -> str:
        """Detailed textual explanation of the policy decision."""
        return self[1]

    def to_dict(self) -> Dict[str, str]:
        """Convert decision result to a dictionary."""
        return {"policy_decision": self.decision, "explanation": self.explanation}

    def __getitem__(self, item: Any) -> Any:
        if isinstance(item, str):
            if item in ("decision", "policy_decision"):
                return self[0]
            if item == "explanation":
                return self[1]
            raise KeyError(f"Invalid key '{item}'. Recognized keys: 'decision', 'explanation'.")
        return super().__getitem__(item)


# ---------------------------------------------------------------------------
# Trust Grade Calculation
# ---------------------------------------------------------------------------

def calculate_trust_grade(
    score: Optional[float],
    config: Optional[Union[TrustEngineConfig, Dict[str, Any]]] = None,
) -> str:
    """Determine the qualitative trust grade strictly based on numerical score.
    
    Grading Rubric:
    - HIGH:        score >= 0.75
    - MEDIUM:      0.45 <= score < 0.75
    - LOW:         score < 0.45
    - UNAVAILABLE: score is None or non-numeric
    
    The trust grade reflects solely the mathematical score. Critical flags and
    governance restrictions are handled independently in the policy decision.
    
    Args:
        score: Normalized trust score in [0.0, 1.0], or None.
        config: Optional TrustEngineConfig or dictionary specifying grade thresholds.
        
    Returns:
        One of 'HIGH', 'MEDIUM', 'LOW', or 'UNAVAILABLE'.
    """
    if score is None:
        return TrustGrade.UNAVAILABLE.value

    # Reject boolean (subclass of int in Python)
    if isinstance(score, bool):
        return TrustGrade.UNAVAILABLE.value

    # Reject non-numeric types
    if not isinstance(score, (int, float)):
        return TrustGrade.UNAVAILABLE.value

    # Reject NaN and Infinity
    if math.isnan(score) or math.isinf(score):
        return TrustGrade.UNAVAILABLE.value

    # Reject out of bounds scores
    if score < 0.0 or score > 1.0:
        return TrustGrade.UNAVAILABLE.value

    high_threshold = DEFAULT_GRADE_THRESHOLDS.get("high", 0.75)
    medium_threshold = DEFAULT_GRADE_THRESHOLDS.get("medium", 0.45)

    if isinstance(config, TrustEngineConfig):
        high_threshold = config.grade_thresholds.get("high", high_threshold)
        medium_threshold = config.grade_thresholds.get("medium", medium_threshold)
    elif isinstance(config, dict):
        if "grade_thresholds" in config and isinstance(config["grade_thresholds"], dict):
            high_threshold = config["grade_thresholds"].get("high", high_threshold)
            medium_threshold = config["grade_thresholds"].get("medium", medium_threshold)
        elif "high" in config and "medium" in config:
            high_threshold = config.get("high", high_threshold)
            medium_threshold = config.get("medium", medium_threshold)

    score_val = float(score)
    if score_val >= high_threshold:
        return TrustGrade.HIGH.value
    elif score_val >= medium_threshold:
        return TrustGrade.MEDIUM.value
    else:
        return TrustGrade.LOW.value


# ---------------------------------------------------------------------------
# Core Decision Function
# ---------------------------------------------------------------------------

def determine_policy_decision(
    overall_trust_score: Optional[float],
    config: Optional[Union[TrustEngineConfig, Dict[str, Any]]] = None,
    flags: Optional[Union[List[str], Tuple[str, ...], set]] = None,
    coverage_ratio: float = 1.0,
    min_coverage: float = DEFAULT_MIN_COVERAGE,
) -> PolicyDecisionResult:
    """Determine the policy decision and explanation given score, flags, and coverage.
    
    Applies:
    1. Score validation (must be float in [0.0, 1.0]).
    2. Policy threshold evaluation (PASS >= 0.75, REVIEW >= 0.45, REJECT < 0.45).
    3. Coverage safety checks (coverage < min_coverage prevents PASS).
    4. Critical flag evaluation (INTEGRITY_MISMATCH, CONTRADICTED_CLAIM, etc. force REVIEW).
    
    Args:
        overall_trust_score: Aggregated trust score or None if unavailable.
        config: Optional TrustEngineConfig or dictionary of thresholds.
        flags: Optional collection of warning/critical flags.
        coverage_ratio: Ratio of evaluated dimensions [0.0, 1.0].
        min_coverage: Minimum coverage ratio required to permit PASS (default: 0.50).
        
    Returns:
        PolicyDecisionResult containing decision ('PASS', 'REVIEW', 'REJECT') and explanation.
    """
    # 1. Resolve policy thresholds
    pass_threshold = DEFAULT_POLICY_THRESHOLDS.get("pass_min_score", 0.75)
    review_threshold = DEFAULT_POLICY_THRESHOLDS.get("review_min_score", 0.45)

    if isinstance(config, TrustEngineConfig):
        pass_threshold = config.policy_thresholds.get("pass_min_score", pass_threshold)
        review_threshold = config.policy_thresholds.get("review_min_score", review_threshold)
    elif isinstance(config, dict):
        if "policy_thresholds" in config and isinstance(config["policy_thresholds"], dict):
            pass_threshold = config["policy_thresholds"].get("pass_min_score", pass_threshold)
            review_threshold = config["policy_thresholds"].get("review_min_score", review_threshold)
        elif "pass_min_score" in config and "review_min_score" in config:
            pass_threshold = config.get("pass_min_score", pass_threshold)
            review_threshold = config.get("review_min_score", review_threshold)

    # 2. Normalize and extract critical flags
    active_flags: List[str] = []
    if flags:
        for f in flags:
            if f is None:
                continue
            f_str = f.value if isinstance(f, CriticalFlag) else str(f).strip().upper()
            if f_str:
                active_flags.append(f_str)

    # 3. Validate coverage ratio
    coverage_issue = False
    invalid_coverage = False
    cov_val = coverage_ratio

    if cov_val is None or isinstance(cov_val, bool) or not isinstance(cov_val, (int, float)):
        coverage_issue = True
        invalid_coverage = True
    elif math.isnan(cov_val) or math.isinf(cov_val) or cov_val < 0.0 or cov_val > 1.0:
        coverage_issue = True
        invalid_coverage = True
    else:
        if cov_val < min_coverage:
            coverage_issue = True
            if CriticalFlag.LOW_COVERAGE.value not in active_flags:
                active_flags.append(CriticalFlag.LOW_COVERAGE.value)

    # 4. Handle None / Insufficient score
    if overall_trust_score is None:
        explanation = "Insufficient data available to compute a trust score; manual review required."
        return PolicyDecisionResult(PolicyDecision.REVIEW, explanation)

    # 5. Handle invalid score types or bounds
    if isinstance(overall_trust_score, bool) or not isinstance(overall_trust_score, (int, float)):
        explanation = (
            f"Invalid trust score '{overall_trust_score}'; score must be a number "
            "between 0.0 and 1.0. Policy mandates REVIEW."
        )
        return PolicyDecisionResult(PolicyDecision.REVIEW, explanation)

    if math.isnan(overall_trust_score) or math.isinf(overall_trust_score):
        explanation = (
            f"Invalid non-finite trust score '{overall_trust_score}'. Policy mandates REVIEW."
        )
        return PolicyDecisionResult(PolicyDecision.REVIEW, explanation)

    score_val = float(overall_trust_score)
    if score_val < 0.0 or score_val > 1.0:
        explanation = (
            f"Trust score {score_val} is out of bounds [0.0, 1.0]. Policy mandates REVIEW."
        )
        return PolicyDecisionResult(PolicyDecision.REVIEW, explanation)

    # 6. Apply policy decision logic
    # Baseline candidate from numerical score
    if score_val >= pass_threshold:
        baseline = PolicyDecision.PASS
    elif score_val >= review_threshold:
        baseline = PolicyDecision.REVIEW
    else:
        baseline = PolicyDecision.REJECT

    # Safety checks if baseline is PASS
    if baseline == PolicyDecision.PASS:
        downgrade_reasons: List[str] = []

        if invalid_coverage:
            downgrade_reasons.append("invalid coverage ratio")
        elif coverage_issue:
            downgrade_reasons.append(f"low coverage ({cov_val:.2f} < {min_coverage:.2f})")

        # Identify any critical flags present
        critical_flags_present = [f for f in active_flags if f in RECOGNIZED_CRITICAL_FLAGS]
        if critical_flags_present:
            downgrade_reasons.append(f"critical flags: {', '.join(sorted(critical_flags_present))}")

        if downgrade_reasons:
            reasons_text = "; ".join(downgrade_reasons)
            explanation = (
                f"Trust score ({score_val:.2f}) meets PASS threshold ({pass_threshold:.2f}) "
                f"but was downgraded to REVIEW due to {reasons_text}."
            )
            return PolicyDecisionResult(PolicyDecision.REVIEW, explanation)

        explanation = "Trust score meets the PASS threshold with sufficient coverage and no critical flags."
        return PolicyDecisionResult(PolicyDecision.PASS, explanation)

    elif baseline == PolicyDecision.REVIEW:
        critical_flags_present = [f for f in active_flags if f in RECOGNIZED_CRITICAL_FLAGS]
        if critical_flags_present:
            explanation = (
                f"Trust score ({score_val:.2f}) falls within REVIEW threshold range "
                f"[{review_threshold:.2f}, {pass_threshold:.2f}) with active flags: "
                f"{', '.join(sorted(critical_flags_present))}."
            )
        else:
            explanation = (
                f"Trust score ({score_val:.2f}) falls within the REVIEW threshold range "
                f"[{review_threshold:.2f}, {pass_threshold:.2f}); manual review required."
            )
        return PolicyDecisionResult(PolicyDecision.REVIEW, explanation)

    else:  # REJECT
        explanation = (
            f"Trust score ({score_val:.2f}) falls below the minimum threshold "
            f"({review_threshold:.2f}) for review; policy decision is REJECT."
        )
        return PolicyDecisionResult(PolicyDecision.REJECT, explanation)


# ---------------------------------------------------------------------------
# Policy Evaluation API
# ---------------------------------------------------------------------------

def evaluate_policy(
    scoring_result: Any,
    flags: Optional[Union[List[str], Tuple[str, ...], set]] = None,
    config: Optional[Union[TrustEngineConfig, Dict[str, Any]]] = None,
    min_coverage: float = DEFAULT_MIN_COVERAGE,
) -> Dict[str, Any]:
    """Evaluate trust scoring results and flags to generate a comprehensive policy report.
    
    Accepts:
    - The output dictionary from `scoring.py` (`calculate_trust_score`).
    - Raw float score.
    - None or empty dictionary.
    
    Args:
        scoring_result: Output from Trust Scoring Engine, float score, or dictionary.
        flags: Optional list of external warning or critical flags.
        config: Optional TrustEngineConfig or dict overriding defaults.
        min_coverage: Minimum coverage ratio required for PASS (default: 0.50).
        
    Returns:
        Structured policy report dictionary:
        {
            "overall_trust_score": Optional[float],
            "trust_grade": str,
            "policy_decision": str,
            "coverage_ratio": float,
            "triggered_flags": List[str],
            "reasons": List[str],
            "warnings": List[str],
            "explanation": str,
            "status": str
        }
    """
    # 1. Unpack scoring_result safely
    overall_trust_score: Optional[float] = None
    coverage_ratio: float = 1.0
    scoring_status: str = PolicyStatus.SUCCESS.value
    unavailable_dimensions: List[str] = []
    dimension_scores: Dict[str, Any] = {}
    validation_errors: List[str] = []
    embedded_flags: List[str] = []
    is_empty_input = False

    if scoring_result is None:
        overall_trust_score = None
        coverage_ratio = 0.0
        scoring_status = PolicyStatus.INSUFFICIENT_DATA.value
        is_empty_input = True
    elif isinstance(scoring_result, (int, float)) and not isinstance(scoring_result, bool):
        overall_trust_score = float(scoring_result)
        coverage_ratio = 1.0
        scoring_status = PolicyStatus.SUCCESS.value
    elif isinstance(scoring_result, dict):
        if not scoring_result:
            overall_trust_score = None
            coverage_ratio = 0.0
            scoring_status = PolicyStatus.INSUFFICIENT_DATA.value
            is_empty_input = True
        else:
            overall_trust_score = scoring_result.get("overall_trust_score")
            coverage_ratio = scoring_result.get("coverage_ratio", 1.0)
            scoring_status = scoring_result.get("status", PolicyStatus.SUCCESS.value)
            unavailable_dimensions = list(scoring_result.get("unavailable_dimensions", []))
            dimension_scores = dict(scoring_result.get("dimension_scores", {}))
            validation_errors = list(scoring_result.get("validation_errors", []))

            # Check if flags were embedded inside scoring_result
            if "flags" in scoring_result and isinstance(scoring_result["flags"], (list, tuple, set)):
                embedded_flags.extend([str(f) for f in scoring_result["flags"]])
            if "triggered_flags" in scoring_result and isinstance(scoring_result["triggered_flags"], (list, tuple, set)):
                embedded_flags.extend([str(f) for f in scoring_result["triggered_flags"]])
    else:
        # Invalid input type
        overall_trust_score = None
        coverage_ratio = 0.0
        scoring_status = PolicyStatus.VALIDATION_ERROR.value
        validation_errors.append(
            f"Input scoring_result must be a dict or number, got {type(scoring_result).__name__}."
        )

    # 2. Combine all flags
    combined_flags: List[str] = []
    for f in embedded_flags:
        if f:
            combined_flags.append(f.strip().upper())
    if flags:
        for f in flags:
            if f is not None:
                f_str = f.value if isinstance(f, CriticalFlag) else str(f).strip().upper()
                if f_str and f_str not in combined_flags:
                    combined_flags.append(f_str)

    # 3. Calculate trust grade
    trust_grade = calculate_trust_grade(overall_trust_score, config=config)

    # 4. Determine policy decision
    decision_res = determine_policy_decision(
        overall_trust_score=overall_trust_score,
        config=config,
        flags=combined_flags,
        coverage_ratio=coverage_ratio,
        min_coverage=min_coverage,
    )
    policy_decision = decision_res.decision
    explanation = decision_res.explanation

    # 5. Formulate triggered_flags list
    triggered_flags: List[str] = []
    for f in combined_flags:
        if f in RECOGNIZED_CRITICAL_FLAGS and f not in triggered_flags:
            triggered_flags.append(f)

    # Auto-flag LOW_COVERAGE if applicable
    if coverage_ratio is not None and isinstance(coverage_ratio, (int, float)) and not isinstance(coverage_ratio, bool):
        if coverage_ratio < min_coverage and CriticalFlag.LOW_COVERAGE.value not in triggered_flags:
            triggered_flags.append(CriticalFlag.LOW_COVERAGE.value)

    # 6. Formulate reasons
    reasons: List[str] = []
    if is_empty_input:
        reasons.append("Empty or missing input received; no trust evaluation data available.")
    elif overall_trust_score is None:
        reasons.append("Overall trust score is unavailable (None); policy mandates REVIEW.")
    elif isinstance(overall_trust_score, bool) or not isinstance(overall_trust_score, (int, float)):
        reasons.append(f"Invalid trust score '{overall_trust_score}'; must be numeric.")
    elif math.isnan(overall_trust_score) or math.isinf(overall_trust_score):
        reasons.append(f"Invalid non-finite trust score '{overall_trust_score}'.")
    elif overall_trust_score < 0.0 or overall_trust_score > 1.0:
        reasons.append(f"Trust score {overall_trust_score} out of bounds [0.0, 1.0].")
    elif policy_decision == PolicyDecision.REJECT.value:
        review_min = DEFAULT_POLICY_THRESHOLDS["review_min_score"]
        if isinstance(config, TrustEngineConfig):
            review_min = config.policy_thresholds.get("review_min_score", review_min)
        elif isinstance(config, dict) and "review_min_score" in config:
            review_min = config["review_min_score"]
        reasons.append(
            f"Overall trust score ({overall_trust_score:.2f}) falls below review threshold ({review_min:.2f})."
        )
    elif policy_decision == PolicyDecision.REVIEW.value:
        pass_min = DEFAULT_POLICY_THRESHOLDS["pass_min_score"]
        if isinstance(config, TrustEngineConfig):
            pass_min = config.policy_thresholds.get("pass_min_score", pass_min)
        elif isinstance(config, dict) and "pass_min_score" in config:
            pass_min = config["pass_min_score"]

        # If score was high enough for PASS but downgraded
        if overall_trust_score >= pass_min:
            for flag in triggered_flags:
                if flag == CriticalFlag.INTEGRITY_MISMATCH.value:
                    reasons.append(
                        "Critical flag 'INTEGRITY_MISMATCH': cryptographic file hash differs from trusted baseline."
                    )
                elif flag == CriticalFlag.CONTRADICTED_CLAIM.value:
                    reasons.append(
                        "Critical flag 'CONTRADICTED_CLAIM': evidence contradicts verified claim."
                    )
                elif flag == CriticalFlag.INCONSISTENT_DATA.value:
                    reasons.append(
                        "Critical flag 'INCONSISTENT_DATA': conflicting numerical, date, or unit values detected across sources."
                    )
                elif flag == CriticalFlag.FUTURE_DATED_EVIDENCE.value:
                    reasons.append(
                        "Critical flag 'FUTURE_DATED_EVIDENCE': evidence publication date is set in the future."
                    )
                elif flag == CriticalFlag.LOW_COVERAGE.value:
                    if isinstance(coverage_ratio, (int, float)) and not isinstance(coverage_ratio, bool):
                        reasons.append(
                            f"Low coverage: evaluated dimensions represent only {coverage_ratio:.2f} "
                            f"of total weight (minimum required: {min_coverage:.2f})."
                        )
                    else:
                        reasons.append(
                            f"Low coverage: invalid coverage ratio '{coverage_ratio}' "
                            f"(minimum required: {min_coverage:.2f})."
                        )
            if not triggered_flags and isinstance(coverage_ratio, (int, float)) and not isinstance(coverage_ratio, bool) and coverage_ratio < min_coverage:
                reasons.append(
                    f"Low coverage: evaluated dimensions represent only {coverage_ratio:.2f} "
                    f"of total weight (minimum required: {min_coverage:.2f})."
                )
        else:
            # Score in REVIEW range [0.45, 0.75)
            reasons.append(
                f"Trust score ({overall_trust_score:.2f}) falls within moderate range [0.45, {pass_min:.2f})."
            )
            for flag in triggered_flags:
                reasons.append(f"Flag '{flag}' present during review evaluation.")

    # 7. Formulate warnings
    warnings: List[str] = []

    # Unavailable dimensions
    for dim in unavailable_dimensions:
        warnings.append(f"Dimension '{dim}' is unavailable (not evaluated).")

    # Coverage warning
    if coverage_ratio is not None and isinstance(coverage_ratio, (int, float)) and not isinstance(coverage_ratio, bool):
        if coverage_ratio < min_coverage:
            warnings.append(
                f"Trust coverage ratio ({coverage_ratio:.2f}) is below standard threshold ({min_coverage:.2f})."
            )
    else:
        warnings.append(f"Invalid coverage ratio '{coverage_ratio}'; expected float between 0.0 and 1.0.")

    # Validation errors from scoring or policy
    for err in validation_errors:
        if err not in warnings:
            warnings.append(err)

    # 8. Determine final operational status
    if scoring_status == PolicyStatus.INSUFFICIENT_DATA.value or overall_trust_score is None:
        status = PolicyStatus.INSUFFICIENT_DATA.value
    elif (
        scoring_status == PolicyStatus.VALIDATION_ERROR.value
        or validation_errors
        or isinstance(overall_trust_score, bool)
        or (overall_trust_score is not None and (overall_trust_score < 0.0 or overall_trust_score > 1.0))
    ):
        status = PolicyStatus.VALIDATION_ERROR.value
    else:
        status = PolicyStatus.SUCCESS.value

    return {
        "overall_trust_score": overall_trust_score,
        "trust_grade": trust_grade,
        "policy_decision": policy_decision,
        "coverage_ratio": coverage_ratio,
        "triggered_flags": triggered_flags,
        "reasons": reasons,
        "warnings": warnings,
        "explanation": explanation,
        "status": status,
    }


# ---------------------------------------------------------------------------
# Structured Report Generator
# ---------------------------------------------------------------------------

def generate_policy_report(
    scoring_result: Optional[Union[Dict[str, Any], float]] = None,
    flags: Optional[Union[List[str], Tuple[str, ...], set]] = None,
    config: Optional[Union[TrustEngineConfig, Dict[str, Any]]] = None,
    min_coverage: float = DEFAULT_MIN_COVERAGE,
    overall_trust_score: Optional[float] = None,
    coverage_ratio: Optional[float] = None,
    policy_decision: Optional[str] = None,
    trust_grade: Optional[str] = None,
    triggered_flags: Optional[List[str]] = None,
    reasons: Optional[List[str]] = None,
    warnings: Optional[List[str]] = None,
    explanation: Optional[str] = None,
    status: Optional[str] = None,
) -> Dict[str, Any]:
    """Return a structured policy report.
    
    If pre-computed fields are provided, returns them formatted in the standard report.
    Otherwise delegates to `evaluate_policy` to compute all fields dynamically.
    """
    if scoring_result is not None or (overall_trust_score is None and policy_decision is None):
        return evaluate_policy(
            scoring_result=scoring_result,
            flags=flags,
            config=config,
            min_coverage=min_coverage,
        )

    # Pre-computed field assembly
    return {
        "overall_trust_score": overall_trust_score,
        "trust_grade": trust_grade or calculate_trust_grade(overall_trust_score, config=config),
        "policy_decision": policy_decision or PolicyDecision.REVIEW.value,
        "coverage_ratio": coverage_ratio if coverage_ratio is not None else 1.0,
        "triggered_flags": triggered_flags or [],
        "reasons": reasons or [],
        "warnings": warnings or [],
        "explanation": explanation or "",
        "status": status or PolicyStatus.SUCCESS.value,
    }


# ---------------------------------------------------------------------------
# PolicyEngine Object-Oriented Interface
# ---------------------------------------------------------------------------

class PolicyEngine:
    """Evaluates trust scores and system flags against governance policies."""

    def __init__(
        self,
        config: Optional[Union[TrustEngineConfig, Dict[str, Any]]] = None,
        policy_thresholds: Optional[Dict[str, float]] = None,
        grade_thresholds: Optional[Dict[str, float]] = None,
        min_coverage: float = DEFAULT_MIN_COVERAGE,
    ):
        """Initialize PolicyEngine with configurable thresholds and coverage bounds.
        
        Args:
            config: Optional TrustEngineConfig or dictionary.
            policy_thresholds: Optional dictionary of pass/review thresholds.
            grade_thresholds: Optional dictionary of high/medium thresholds.
            min_coverage: Minimum coverage ratio required for PASS (default: 0.50).
        """
        if isinstance(config, TrustEngineConfig):
            self.config = config
        elif isinstance(config, dict):
            self.config = config
        else:
            self.config = TrustEngineConfig(
                policy_thresholds=policy_thresholds or DEFAULT_POLICY_THRESHOLDS.copy(),
                grade_thresholds=grade_thresholds or DEFAULT_GRADE_THRESHOLDS.copy(),
            )

        self.policy_thresholds = (
            policy_thresholds
            or (self.config.policy_thresholds if isinstance(self.config, TrustEngineConfig) else DEFAULT_POLICY_THRESHOLDS)
        )
        self.grade_thresholds = (
            grade_thresholds
            or (self.config.grade_thresholds if isinstance(self.config, TrustEngineConfig) else DEFAULT_GRADE_THRESHOLDS)
        )
        self.min_coverage = min_coverage

    def determine_grade(self, score: Optional[float]) -> str:
        """Map a normalized trust score to a qualitative grade (HIGH, MEDIUM, LOW, UNAVAILABLE)."""
        return calculate_trust_grade(score, config=self.config)

    def determine_decision(
        self,
        overall_trust_score: Optional[float],
        flags: Optional[Union[List[str], Tuple[str, ...], set]] = None,
        coverage_ratio: float = 1.0,
    ) -> PolicyDecisionResult:
        """Determine policy decision and explanation given score, flags, and coverage."""
        return determine_policy_decision(
            overall_trust_score=overall_trust_score,
            config=self.config,
            flags=flags,
            coverage_ratio=coverage_ratio,
            min_coverage=self.min_coverage,
        )

    def evaluate(
        self,
        scoring_result: Any,
        flags: Optional[Union[List[str], Tuple[str, ...], set]] = None,
    ) -> Dict[str, Any]:
        """Produce the complete governance evaluation and policy report."""
        return evaluate_policy(
            scoring_result=scoring_result,
            flags=flags,
            config=self.config,
            min_coverage=self.min_coverage,
        )

    def generate_report(
        self,
        scoring_result: Any,
        flags: Optional[Union[List[str], Tuple[str, ...], set]] = None,
    ) -> Dict[str, Any]:
        """Alias for evaluate(); generates a structured policy report."""
        return self.evaluate(scoring_result=scoring_result, flags=flags)

    def evaluate_policy(
        self,
        overall_score: Any,
        dimension_scores: Optional[Dict[str, Any]] = None,
        flags: Optional[Union[List[str], Tuple[str, ...], set]] = None,
    ) -> Dict[str, Any]:
        """Produce the final governance decision (backwards compatibility)."""
        if isinstance(overall_score, dict):
            return self.evaluate(scoring_result=overall_score, flags=flags)

        scoring_dict = {
            "overall_trust_score": overall_score,
            "dimension_scores": dimension_scores or {},
            "coverage_ratio": 1.0,
            "status": PolicyStatus.SUCCESS.value if overall_score is not None else PolicyStatus.INSUFFICIENT_DATA.value,
        }
        return self.evaluate(scoring_dict, flags=flags)
