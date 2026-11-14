"""Freshness Checker Component for VerityOS.

This module evaluates the temporal relevance, recency, and age of evidence items
based on their publication and update dates.

Architectural Principles:
1. Recency vs. Correctness:
   Freshness measures information recency, NOT factual correctness. Old information
   is not automatically false; however, in fast-evolving domains (financial, legal,
   medical, tech), older data has higher probability of obsolescence.
2. Explicit Score Unavailability:
   Missing or unparseable dates are explicitly marked as unavailable (`freshness_score = None`),
   NEVER falsely assumed to be 100% fresh or 0% fresh.
3. Future Date Safeguard:
   Future-dated publications are flagged as `FUTURE_DATED` and not silently treated as fresh.
4. Timezone Safety:
   All temporal calculations normalize timezone differences safely.
5. Deterministic Testing:
   Supports an optional `reference_date` parameter across all functions to allow
   fully reproducible unit tests without depending on the system clock.
"""

from datetime import date, datetime, timezone
from enum import Enum
import re
from typing import Any, Dict, List, Optional, Tuple, Union

from trust_engine.config import DEFAULT_MAX_FRESHNESS_DAYS


# ---------------------------------------------------------------------------
# Enums and Default Thresholds
# ---------------------------------------------------------------------------

class FreshnessStatus(str, Enum):
    """Qualitative status categories for evidence freshness."""
    FRESH = "FRESH"                 # Recent data within the fresh threshold (e.g. <= 30 days)
    AGING = "AGING"                 # Moderately aged data (e.g. 31 to 180 days)
    STALE = "STALE"                 # Outdated data beyond the aging threshold (> 180 days)
    UNKNOWN = "UNKNOWN"             # Publication date was not provided
    INVALID_DATE = "INVALID_DATE"   # Date was provided but could not be parsed
    FUTURE_DATED = "FUTURE_DATED"   # Publication date lies in the future relative to evaluation date


# Default Age Thresholds in Days
DEFAULT_FRESH_MAX_DAYS: int = 30
DEFAULT_AGING_MAX_DAYS: int = 180
DEFAULT_STALE_MAX_DAYS: int = DEFAULT_MAX_FRESHNESS_DAYS  # 365 days


# ---------------------------------------------------------------------------
# Extraction & Date Parsing Helpers
# ---------------------------------------------------------------------------

def extract_publication_date_raw(evidence: Any) -> Optional[Any]:
    """Extract raw publication date value from an Evidence model or dictionary.
    
    Args:
        evidence: Pydantic Evidence instance or dictionary.
        
    Returns:
        Raw value of publication_date (str, date, datetime, or None).
    """
    if evidence is None:
        return None
    if isinstance(evidence, dict):
        return evidence.get("publication_date")
    return getattr(evidence, "publication_date", None)


def parse_date_value(date_val: Any) -> Tuple[Optional[datetime], Optional[str]]:
    """Parse various date representations into a standardized datetime.
    
    Supports:
    - Python datetime objects (tz-naive and tz-aware)
    - Python date objects
    - ISO 8601 strings (YYYY-MM-DD, YYYY-MM-DDTHH:MM:SS, with/without Z or tz offset)
    
    Args:
        date_val: Raw date input.
        
    Returns:
        Tuple of (parsed_datetime_utc, error_message).
        If date_val is None or empty, returns (None, None).
        If invalid, returns (None, error_description).
    """
    if date_val is None:
        return None, None

    # Already a datetime object
    if isinstance(date_val, datetime):
        if date_val.tzinfo is not None and date_val.tzinfo.utcoffset(date_val) is not None:
            return date_val.astimezone(timezone.utc), None
        return date_val.replace(tzinfo=timezone.utc), None

    # Python date object (convert to start of day UTC)
    if isinstance(date_val, date):
        return datetime(date_val.year, date_val.month, date_val.day, tzinfo=timezone.utc), None

    # String parsing
    if isinstance(date_val, str):
        cleaned = date_val.strip()
        if not cleaned:
            return None, None

        # Replace 'Z' with UTC offset '+00:00' for broad ISO compatibility
        norm_str = cleaned
        if norm_str.endswith("Z"):
            norm_str = norm_str[:-1] + "+00:00"

        # Attempt ISO 8601 fromisoformat (supports YYYY-MM-DD and full ISO timestamps)
        try:
            dt = datetime.fromisoformat(norm_str)
            if dt.tzinfo is not None and dt.tzinfo.utcoffset(dt) is not None:
                return dt.astimezone(timezone.utc), None
            return dt.replace(tzinfo=timezone.utc), None
        except (ValueError, TypeError):
            pass

        # Fallback common formats
        for fmt in ("%Y-%m-%d", "%Y/%m/%d", "%d-%m-%Y", "%Y-%m-%d %H:%M:%S"):
            try:
                dt = datetime.strptime(cleaned, fmt)
                return dt.replace(tzinfo=timezone.utc), None
            except ValueError:
                continue

        return None, f"Unrecognized date format: '{cleaned}'"

    return None, f"Unsupported date type: '{type(date_val).__name__}'"


def extract_publication_date(evidence: Any) -> Tuple[Optional[datetime], Optional[str], Optional[str]]:
    """Extract and parse publication date from an evidence item.
    
    Args:
        evidence: Evidence item (Pydantic model or dictionary).
        
    Returns:
        Tuple of (parsed_datetime, raw_string_representation, error_message).
    """
    raw_val = extract_publication_date_raw(evidence)
    if raw_val is None:
        return None, None, None

    raw_str = raw_val.isoformat() if isinstance(raw_val, (date, datetime)) else str(raw_val)
    parsed_dt, error = parse_date_value(raw_val)
    return parsed_dt, raw_str, error


# ---------------------------------------------------------------------------
# Core Calculation Functions
# ---------------------------------------------------------------------------

def calculate_evidence_age(
    publication_date: Any,
    reference_date: Optional[Union[datetime, date, str]] = None
) -> Tuple[Optional[int], Optional[str]]:
    """Calculate the age of evidence in calendar days relative to a reference date.
    
    Timezone-safe: normalizes both publication date and reference date to UTC dates.
    
    Args:
        publication_date: Raw date or datetime input.
        reference_date: Optional reference point. Defaults to current UTC date.
        
    Returns:
        Tuple of (age_in_days, error_message).
        If publication_date is missing: returns (None, None).
        If publication_date is invalid: returns (None, error_str).
        If age_in_days < 0: returns (negative_int, None), representing a future date.
    """
    parsed_pub, raw_str, err = extract_publication_date({"publication_date": publication_date})
    if err:
        return None, err
    if parsed_pub is None:
        return None, None

    # Parse reference date
    if reference_date is None:
        ref_dt = datetime.now(timezone.utc)
    else:
        ref_dt, ref_err = parse_date_value(reference_date)
        if ref_err or ref_dt is None:
            raise ValueError(f"Invalid reference_date provided: '{reference_date}'. {ref_err}")

    # Calculate difference in calendar days
    pub_calendar_date = parsed_pub.date()
    ref_calendar_date = ref_dt.date()
    age_days = (ref_calendar_date - pub_calendar_date).days

    return age_days, None


def calculate_freshness_score(
    age_days: int,
    fresh_max_days: int = DEFAULT_FRESH_MAX_DAYS,
    aging_max_days: int = DEFAULT_AGING_MAX_DAYS,
    stale_max_days: int = DEFAULT_STALE_MAX_DAYS
) -> Optional[float]:
    """Calculate a normalized freshness score (0.0 to 1.0) based on age in days.
    
    Decay Rubric:
    1. FRESH (0 to fresh_max_days):
       Score decays linearly from 1.00 (day 0) down to 0.80.
    2. AGING (fresh_max_days + 1 to aging_max_days):
       Score decays linearly from 0.79 down to 0.40.
    3. STALE (aging_max_days + 1 to stale_max_days+):
       Score decays from 0.39 down to 0.00 at stale_max_days.
    4. FUTURE or NEGATIVE:
       Returns None (cannot assign a positive freshness score to future dates).
       
    Args:
        age_days: Age in calendar days.
        fresh_max_days: Cutoff for FRESH status.
        aging_max_days: Cutoff for AGING status.
        stale_max_days: Age at which STALE score reaches 0.0.
        
    Returns:
        Float score between 0.0 and 1.0, or None if age is negative.
    """
    if age_days < 0:
        return None

    if age_days <= fresh_max_days:
        # Linear decay: [1.0 -> 0.80]
        ratio = age_days / fresh_max_days if fresh_max_days > 0 else 0.0
        return round(1.0 - (0.20 * ratio), 4)

    if age_days <= aging_max_days:
        # Linear decay: [0.79 -> 0.40]
        span = aging_max_days - fresh_max_days
        ratio = (age_days - fresh_max_days) / span if span > 0 else 0.0
        return round(0.79 - (0.39 * ratio), 4)

    # STALE: [0.39 -> 0.00]
    span = stale_max_days - aging_max_days
    if span <= 0 or age_days >= stale_max_days:
        return 0.0
    ratio = (age_days - aging_max_days) / span
    return round(max(0.0, 0.39 * (1.0 - ratio)), 4)


# ---------------------------------------------------------------------------
# Evaluation & Report Generation
# ---------------------------------------------------------------------------

def evaluate_freshness(
    evidence: Any,
    config: Optional[Dict[str, Any]] = None,
    reference_date: Optional[Union[datetime, date, str]] = None
) -> Dict[str, Any]:
    """Evaluate evidence freshness and return classification and score.
    
    Args:
        evidence: Evidence item (Pydantic model or dictionary).
        config: Optional configuration dictionary overriding thresholds.
        reference_date: Optional reference point for deterministic evaluation.
        
    Returns:
        Dictionary with status, age_days, freshness_score, issues, and raw date.
    """
    conf = config or {}
    fresh_max = conf.get("fresh_max_days", DEFAULT_FRESH_MAX_DAYS)
    aging_max = conf.get("aging_max_days", DEFAULT_AGING_MAX_DAYS)
    stale_max = conf.get("stale_max_days", DEFAULT_STALE_MAX_DAYS)

    parsed_dt, raw_date_str, parse_err = extract_publication_date(evidence)
    issues: List[str] = []

    # Case 1: Missing date
    if raw_date_str is None:
        issues.append("Missing publication date. Freshness dimension marked unavailable.")
        return {
            "freshness_status": FreshnessStatus.UNKNOWN.value,
            "publication_date": None,
            "age_days": None,
            "freshness_score": None,
            "issues": issues,
        }

    # Case 2: Invalid/unparseable date
    if parse_err is not None:
        issues.append(f"Invalid publication date: {parse_err}")
        return {
            "freshness_status": FreshnessStatus.INVALID_DATE.value,
            "publication_date": raw_date_str,
            "age_days": None,
            "freshness_score": None,
            "issues": issues,
        }

    # Case 3: Calculate age
    age_days, age_err = calculate_evidence_age(parsed_dt, reference_date=reference_date)
    if age_err is not None:
        issues.append(f"Error calculating age: {age_err}")
        return {
            "freshness_status": FreshnessStatus.INVALID_DATE.value,
            "publication_date": raw_date_str,
            "age_days": None,
            "freshness_score": None,
            "issues": issues,
        }

    # Case 4: Future date
    if age_days < 0:
        issues.append(f"Publication date lies in the future ({abs(age_days)} days ahead).")
        return {
            "freshness_status": FreshnessStatus.FUTURE_DATED.value,
            "publication_date": raw_date_str,
            "age_days": age_days,
            "freshness_score": None,
            "issues": issues,
        }

    # Case 5: Valid historical age
    score = calculate_freshness_score(
        age_days,
        fresh_max_days=fresh_max,
        aging_max_days=aging_max,
        stale_max_days=stale_max,
    )

    if age_days <= fresh_max:
        status = FreshnessStatus.FRESH.value
    elif age_days <= aging_max:
        status = FreshnessStatus.AGING.value
    else:
        status = FreshnessStatus.STALE.value

    return {
        "freshness_status": status,
        "publication_date": raw_date_str,
        "age_days": age_days,
        "freshness_score": score,
        "issues": issues,
    }


def generate_freshness_report(
    evidence: Any,
    config: Optional[Dict[str, Any]] = None,
    reference_date: Optional[Union[datetime, date, str]] = None
) -> Dict[str, Any]:
    """Generate a structured diagnostic freshness report for an evidence item.
    
    Args:
        evidence: Evidence item (Pydantic model or dictionary).
        config: Optional configuration dictionary.
        reference_date: Optional reference point for deterministic evaluation.
        
    Returns:
        Structured report dictionary containing:
        - evidence_id: str
        - publication_date: Optional[str]
        - age_days: Optional[int]
        - freshness_status: str (FRESH, AGING, STALE, UNKNOWN, INVALID_DATE, FUTURE_DATED)
        - freshness_score: Optional[float]
        - issues: List[str]
        - explanation: str
    """
    eval_res = evaluate_freshness(evidence, config=config, reference_date=reference_date)

    # Extract evidence_id safely
    eid = None
    if isinstance(evidence, dict):
        eid = evidence.get("evidence_id")
    elif evidence is not None:
        eid = getattr(evidence, "evidence_id", None)
    evidence_id = str(eid).strip() if eid else "unknown"

    status = eval_res["freshness_status"]
    age_days = eval_res["age_days"]
    score = eval_res["freshness_score"]
    pub_date = eval_res["publication_date"]

    # Generate explanatory rationale
    if status == FreshnessStatus.FRESH.value:
        explanation = (
            f"Evidence '{evidence_id}' published on {pub_date} is {age_days} day(s) old "
            f"and classified as FRESH (score: {score:.2f})."
        )
    elif status == FreshnessStatus.AGING.value:
        explanation = (
            f"Evidence '{evidence_id}' published on {pub_date} is {age_days} day(s) old "
            f"and classified as AGING (score: {score:.2f}). Information remains valid but is aging."
        )
    elif status == FreshnessStatus.STALE.value:
        explanation = (
            f"Evidence '{evidence_id}' published on {pub_date} is {age_days} day(s) old "
            f"and classified as STALE (score: {score:.2f}). Consider verifying against more recent sources."
        )
    elif status == FreshnessStatus.FUTURE_DATED.value:
        explanation = (
            f"Evidence '{evidence_id}' has a future publication date ({pub_date}, {abs(age_days)} days ahead). "
            "Cannot evaluate future-dated content as fresh; score is marked unavailable."
        )
    elif status == FreshnessStatus.INVALID_DATE.value:
        explanation = (
            f"Evidence '{evidence_id}' provided an invalid or unparseable publication date '{pub_date}'. "
            "Freshness score is marked unavailable."
        )
    else:  # UNKNOWN
        explanation = (
            f"Evidence '{evidence_id}' has no publication date recorded. "
            "Freshness dimension is marked unavailable."
        )

    return {
        "evidence_id": evidence_id,
        "publication_date": pub_date,
        "age_days": age_days,
        "freshness_status": status,
        "freshness_score": score,
        "issues": eval_res["issues"],
        "explanation": explanation,
    }


# ---------------------------------------------------------------------------
# Object-Oriented Component Wrapper
# ---------------------------------------------------------------------------

class FreshnessChecker:
    """Evaluates the temporal freshness of evidence items."""

    def __init__(
        self,
        config: Optional[Dict[str, Any]] = None,
        fresh_max_days: int = DEFAULT_FRESH_MAX_DAYS,
        aging_max_days: int = DEFAULT_AGING_MAX_DAYS,
        max_days: int = DEFAULT_STALE_MAX_DAYS,
        reference_date: Optional[Union[datetime, date, str]] = None,
    ):
        """Initialize FreshnessChecker with configurable thresholds.
        
        Args:
            config: Optional configuration dictionary.
            fresh_max_days: Threshold for FRESH status (default 30 days).
            aging_max_days: Threshold for AGING status (default 180 days).
            max_days: Threshold where STALE score reaches 0.0 (default 365 days).
            reference_date: Optional fixed reference date for deterministic testing.
        """
        self.config = config.copy() if config else {}
        self.config.setdefault("fresh_max_days", fresh_max_days)
        self.config.setdefault("aging_max_days", aging_max_days)
        self.config.setdefault("stale_max_days", max_days)
        self.reference_date = reference_date

    def evaluate_evidence(
        self,
        evidence: Any,
        reference_date: Optional[Union[datetime, date, str]] = None
    ) -> Dict[str, Any]:
        """Evaluate freshness of a single evidence item.
        
        Args:
            evidence: Evidence item (Pydantic model or dictionary).
            reference_date: Optional reference date override.
            
        Returns:
            Structured diagnostic report dictionary.
        """
        ref = reference_date if reference_date is not None else self.reference_date
        return generate_freshness_report(evidence, config=self.config, reference_date=ref)

    def assess_freshness(self, timestamp: Optional[str]) -> Dict[str, Any]:
        """Legacy helper assessing freshness of a single timestamp string."""
        return self.evaluate_evidence({"publication_date": timestamp})

    def evaluate_evidences(
        self,
        evidence_list: List[Any],
        reference_date: Optional[Union[datetime, date, str]] = None
    ) -> Dict[str, Any]:
        """Evaluate freshness across a batch of evidence items.
        
        Averages only available scores without assuming missing dates are perfect.
        
        Args:
            evidence_list: List of Evidence items or dictionaries.
            reference_date: Optional reference date override.
            
        Returns:
            Batch summary dictionary containing:
            - total_evidence_count: int
            - fresh_count: int
            - aging_count: int
            - stale_count: int
            - unknown_count: int
            - future_count: int
            - invalid_count: int
            - available_scores_count: int
            - average_freshness_score: Optional[float] (None if no scores available)
            - reports: List of individual reports
        """
        if not evidence_list or not isinstance(evidence_list, list):
            return {
                "total_evidence_count": 0,
                "fresh_count": 0,
                "aging_count": 0,
                "stale_count": 0,
                "unknown_count": 0,
                "future_count": 0,
                "invalid_count": 0,
                "available_scores_count": 0,
                "average_freshness_score": None,
                "reports": [],
            }

        ref = reference_date if reference_date is not None else self.reference_date
        reports: List[Dict[str, Any]] = []
        available_scores: List[float] = []

        fresh_count = 0
        aging_count = 0
        stale_count = 0
        unknown_count = 0
        future_count = 0
        invalid_count = 0

        for item in evidence_list:
            rep = self.evaluate_evidence(item, reference_date=ref)
            reports.append(rep)

            status = rep["freshness_status"]
            if status == FreshnessStatus.FRESH.value:
                fresh_count += 1
            elif status == FreshnessStatus.AGING.value:
                aging_count += 1
            elif status == FreshnessStatus.STALE.value:
                stale_count += 1
            elif status == FreshnessStatus.FUTURE_DATED.value:
                future_count += 1
            elif status == FreshnessStatus.INVALID_DATE.value:
                invalid_count += 1
            else:
                unknown_count += 1

            if rep["freshness_score"] is not None:
                available_scores.append(rep["freshness_score"])

        avg_score = (
            round(sum(available_scores) / len(available_scores), 4)
            if available_scores
            else None
        )

        return {
            "total_evidence_count": len(reports),
            "fresh_count": fresh_count,
            "aging_count": aging_count,
            "stale_count": stale_count,
            "unknown_count": unknown_count,
            "future_count": future_count,
            "invalid_count": invalid_count,
            "available_scores_count": len(available_scores),
            "average_freshness_score": avg_score,
            "reports": reports,
        }

    def evaluate_freshness(self, evidence_list: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Backward-compatible alias for evaluate_evidences."""
        return self.evaluate_evidences(evidence_list)
