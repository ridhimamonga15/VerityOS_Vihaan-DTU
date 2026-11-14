"""Consistency Checker Component for VerityOS.

This module performs deterministic structured comparison across evidence items
associated with the same claim or metric.

Architectural Principles:
1. Structured Comparison Only:
   Evaluates structured numbers, units, dates, and reporting periods. Does NOT
   attempt ungrounded NLP inference from arbitrary free-text snippets.
2. Boundary with Verification Agent:
   Semantic claim verification is performed by Member 1's Verification Agent.
   The Consistency Checker evaluates whether the backing structured data agrees,
   disagrees, uses convertible units, or represents different reporting periods.
3. Equivalent vs. Contradictory:
   - 50 kg and 50,000 g are equivalent, not contradictory.
   - Different reporting periods (e.g. Q1 2024 vs Q2 2024) are distinct temporal
     contexts, not internal factual contradictions.
   - Unconvertible units (e.g. currencies without exchange rates, or kg vs km)
     are marked as INCOMPATIBLE_UNITS / UNKNOWN, not assumed contradictory.
4. Missing Data Policy:
   Missing structured data is represented as unavailable (`consistency_score = None`),
   never artificially assumed to be 100% consistent or 0% consistent.
"""

from datetime import date, datetime
from enum import Enum
import math
import re
from typing import Any, Dict, List, Optional, Tuple, Union
from urllib.parse import urlparse

from trust_engine.freshness_checker import parse_date_value


# ---------------------------------------------------------------------------
# Enums and Statuses
# ---------------------------------------------------------------------------

class ConsistencyStatus(str, Enum):
    """Overall status of consistency evaluation for a claim or metric."""
    CONSISTENT = "CONSISTENT"           # All comparable values agree within tolerance
    INCONSISTENT = "INCONSISTENT"       # Structured values contradict each other
    MIXED = "MIXED"                     # Some values agree, others contradict
    INCOMPATIBLE_UNITS = "INCOMPATIBLE_UNITS" # Units cannot be converted (e.g. kg vs km, currencies)
    INSUFFICIENT = "INSUFFICIENT"       # No structured values available for comparison
    UNKNOWN = "UNKNOWN"                 # Inconclusive comparison or missing essential metadata


class ValueComparisonStatus(str, Enum):
    """Detailed result status for a single pairwise comparison."""
    CONSISTENT = "CONSISTENT"
    INCONSISTENT = "INCONSISTENT"
    INCOMPATIBLE_UNITS = "INCOMPATIBLE_UNITS"
    INVALID_VALUE = "INVALID_VALUE"
    MISSING_VALUE = "MISSING_VALUE"


class DateComparisonStatus(str, Enum):
    """Result status for date comparison."""
    MATCHING = "MATCHING"
    DIFFERENT = "DIFFERENT"
    INVALID = "INVALID"
    MISSING = "MISSING"


class PeriodComparisonStatus(str, Enum):
    """Result status for reporting period comparison."""
    SAME_PERIOD = "SAME_PERIOD"
    DIFFERENT_PERIODS = "DIFFERENT_PERIODS"
    INVALID = "INVALID"
    MISSING = "MISSING"


# ---------------------------------------------------------------------------
# Documented Unit Conversion System
# ---------------------------------------------------------------------------

# Conversion factors to canonical base units:
# Mass: base = "kg"
# Length: base = "m"
# Volume: base = "l"
# Ratio: base = "ratio"
# Count: base = "count"

UNIT_SYSTEMS: Dict[str, Tuple[str, Dict[str, float]]] = {
    "mass": (
        "kg",
        {
            "kg": 1.0,
            "kilogram": 1.0,
            "kilograms": 1.0,
            "g": 0.001,
            "gram": 0.001,
            "grams": 0.001,
            "mg": 0.000001,
            "milligram": 0.000001,
            "milligrams": 0.000001,
            "t": 1000.0,
            "ton": 1000.0,
            "tons": 1000.0,
            "metric_ton": 1000.0,
            "lb": 0.45359237,
            "pound": 0.45359237,
            "pounds": 0.45359237,
            "oz": 0.028349523125,
            "ounce": 0.028349523125,
            "ounces": 0.028349523125,
        },
    ),
    "length": (
        "m",
        {
            "m": 1.0,
            "meter": 1.0,
            "meters": 1.0,
            "km": 1000.0,
            "kilometer": 1000.0,
            "kilometers": 1000.0,
            "cm": 0.01,
            "centimeter": 0.01,
            "centimeters": 0.01,
            "mm": 0.001,
            "millimeter": 0.001,
            "millimeters": 0.001,
            "mi": 1609.344,
            "mile": 1609.344,
            "miles": 1609.344,
            "yd": 0.9144,
            "yard": 0.9144,
            "yards": 0.9144,
            "ft": 0.3048,
            "foot": 0.3048,
            "feet": 0.3048,
            "in": 0.0254,
            "inch": 0.0254,
            "inches": 0.0254,
        },
    ),
    "volume": (
        "l",
        {
            "l": 1.0,
            "liter": 1.0,
            "liters": 1.0,
            "ml": 0.001,
            "milliliter": 0.001,
            "milliliters": 0.001,
            "m3": 1000.0,
            "cubic_meter": 1000.0,
            "cubic_meters": 1000.0,
        },
    ),
    "percentage": (
        "ratio",
        {
            "%": 0.01,
            "percent": 0.01,
            "percentage": 0.01,
            "ratio": 1.0,
        },
    ),
    "dimensionless": (
        "count",
        {
            "count": 1.0,
            "unit": 1.0,
            "units": 1.0,
            "dimensionless": 1.0,
            "": 1.0,
        },
    ),
}

# Known currencies: explicitly identified as non-convertible without real-time exchange rates
NON_CONVERTIBLE_CURRENCIES = {
    "usd", "$", "eur", "€", "gbp", "£", "jpy", "¥", "inr", "₹", "cad", "aud", "cny", "chf"
}


# ---------------------------------------------------------------------------
# Numerical Normalization & Comparison
# ---------------------------------------------------------------------------

def normalize_numeric_value(
    value: Any,
    unit: Optional[str] = None
) -> Tuple[Optional[float], Optional[str], Optional[str]]:
    """Safely normalize a numerical value and unit to a canonical base unit.
    
    Supported unit dimensions:
    - Mass (base: kg) -> kg, g, mg, t, lb, oz
    - Length (base: m) -> m, km, cm, mm, mi, yd, ft, in
    - Volume (base: l) -> l, ml, m3
    - Percentage (base: ratio) -> %, percent, ratio
    - Dimensionless (base: count) -> count, units, none
    
    Currency Policy:
    Different currencies are NOT converted because reliable currency conversion
    requires real-time exchange rates.
    
    Args:
        value: Numeric value (int, float, or parseable string).
        unit: Optional unit string (e.g. "kg", "km", "%").
        
    Returns:
        Tuple of (normalized_value, canonical_base_unit, error_message).
    """
    if value is None:
        return None, None, "Value is missing (None)."

    # Extract unit embedded in string if unit is not explicitly passed (e.g. "50 kg")
    parsed_unit = unit.strip().lower() if unit is not None and str(unit).strip() else None
    parsed_num: Optional[float] = None

    if isinstance(value, (int, float)):
        if math.isnan(value) or math.isinf(value):
            return None, None, "Value cannot be NaN or infinite."
        parsed_num = float(value)
    elif isinstance(value, str):
        cleaned_str = value.strip()
        if not cleaned_str:
            return None, None, "Value string is empty."

        # Regex to separate number and embedded unit (e.g. "50.5 kg" or "100%")
        match = re.match(r"^([+-]?\d+(?:\.\d+)?(?:[eE][+-]?\d+)?)\s*([a-zA-Z%€$£¥₹]+)?$", cleaned_str)
        if match:
            num_part = match.group(1)
            embedded_unit = match.group(2)
            try:
                parsed_num = float(num_part)
            except ValueError:
                return None, None, f"Could not parse numeric string: '{value}'."

            if parsed_unit is None and embedded_unit:
                parsed_unit = embedded_unit.strip().lower()
        else:
            try:
                parsed_num = float(cleaned_str)
            except ValueError:
                return None, None, f"Invalid numeric value string: '{value}'."
    else:
        return None, None, f"Unsupported value type: '{type(value).__name__}'."

    # If no unit, treat as dimensionless count
    if not parsed_unit:
        return parsed_num, "count", None

    # Check for currency
    if parsed_unit in NON_CONVERTIBLE_CURRENCIES:
        return parsed_num, f"currency:{parsed_unit}", None

    # Search through supported unit systems
    for dim_name, (base_unit, units_dict) in UNIT_SYSTEMS.items():
        if parsed_unit in units_dict:
            factor = units_dict[parsed_unit]
            normalized = round(parsed_num * factor, 8)
            return normalized, base_unit, None

    # Unknown / unmapped unit: preserve as-is under custom label
    return parsed_num, f"custom:{parsed_unit}", None


def compare_numeric_values(
    value1: Any,
    value2: Any,
    unit1: Optional[str] = None,
    unit2: Optional[str] = None,
    tolerance: float = 0.0
) -> Dict[str, Any]:
    """Compare two numerical values with unit normalization and tolerance.
    
    Args:
        value1: First value (numeric or string).
        value2: Second value (numeric or string).
        unit1: Unit for first value.
        unit2: Unit for second value.
        tolerance: Maximum allowable difference to consider values equivalent.
        
    Returns:
        Dictionary containing:
        - is_equivalent: bool
        - comparison_status: ValueComparisonStatus string
        - normalized_value1: Optional[float]
        - normalized_value2: Optional[float]
        - canonical_unit: Optional[str]
        - difference: Optional[float]
        - tolerance: float
        - explanation: str
    """
    if tolerance < 0:
        raise ValueError(f"tolerance must be non-negative, got {tolerance}.")

    # Missing check
    if value1 is None or value2 is None:
        return {
            "is_equivalent": False,
            "comparison_status": ValueComparisonStatus.MISSING_VALUE.value,
            "normalized_value1": None,
            "normalized_value2": None,
            "canonical_unit": None,
            "difference": None,
            "tolerance": tolerance,
            "explanation": "One or both numerical values are missing (None).",
        }

    norm1, base_unit1, err1 = normalize_numeric_value(value1, unit1)
    norm2, base_unit2, err2 = normalize_numeric_value(value2, unit2)

    # Invalid check
    if err1 or err2:
        reasons = []
        if err1:
            reasons.append(f"Value 1: {err1}")
        if err2:
            reasons.append(f"Value 2: {err2}")
        return {
            "is_equivalent": False,
            "comparison_status": ValueComparisonStatus.INVALID_VALUE.value,
            "normalized_value1": norm1,
            "normalized_value2": norm2,
            "canonical_unit": None,
            "difference": None,
            "tolerance": tolerance,
            "explanation": "Invalid numeric input: " + "; ".join(reasons),
        }

    # Incompatible units check
    if base_unit1 != base_unit2:
        return {
            "is_equivalent": False,
            "comparison_status": ValueComparisonStatus.INCOMPATIBLE_UNITS.value,
            "normalized_value1": norm1,
            "normalized_value2": norm2,
            "canonical_unit": f"{base_unit1} vs {base_unit2}",
            "difference": None,
            "tolerance": tolerance,
            "explanation": (
                f"Cannot compare values with incompatible units: '{base_unit1}' and '{base_unit2}'. "
                "No safe conversion exists without external conversion rates."
            ),
        }

    # Calculate difference
    diff = round(abs(norm1 - norm2), 8)
    is_equiv = diff <= tolerance

    if is_equiv:
        explanation = (
            f"Values are equivalent: {norm1} {base_unit1} and {norm2} {base_unit2} "
            f"(difference {diff} <= tolerance {tolerance})."
        )
        status = ValueComparisonStatus.CONSISTENT.value
    else:
        explanation = (
            f"Values differ: {norm1} {base_unit1} vs {norm2} {base_unit2} "
            f"(difference {diff} > tolerance {tolerance})."
        )
        status = ValueComparisonStatus.INCONSISTENT.value

    return {
        "is_equivalent": is_equiv,
        "comparison_status": status,
        "normalized_value1": norm1,
        "normalized_value2": norm2,
        "canonical_unit": base_unit1,
        "difference": diff,
        "tolerance": tolerance,
        "explanation": explanation,
    }


# ---------------------------------------------------------------------------
# Date & Reporting Period Comparison
# ---------------------------------------------------------------------------

def compare_dates(date1: Any, date2: Any) -> Dict[str, Any]:
    """Compare two date representations for temporal equivalence.
    
    Args:
        date1: First date (string, date, or datetime).
        date2: Second date (string, date, or datetime).
        
    Returns:
        Dictionary with comparison status, parsed dates, difference in days,
        and explanatory note.
    """
    if date1 is None or date2 is None:
        return {
            "is_matching": False,
            "comparison_status": DateComparisonStatus.MISSING.value,
            "date1": None,
            "date2": None,
            "difference_days": None,
            "explanation": "One or both date values are missing (None).",
        }

    dt1, err1 = parse_date_value(date1)
    dt2, err2 = parse_date_value(date2)

    if err1 or err2:
        return {
            "is_matching": False,
            "comparison_status": DateComparisonStatus.INVALID.value,
            "date1": str(date1),
            "date2": str(date2),
            "difference_days": None,
            "explanation": f"Invalid date format: {err1 or err2}.",
        }

    d1 = dt1.date()
    d2 = dt2.date()
    diff_days = abs((d1 - d2).days)
    is_match = diff_days == 0

    if is_match:
        explanation = f"Dates match: {d1.isoformat()} and {d2.isoformat()} represent the same calendar day."
        status = DateComparisonStatus.MATCHING.value
    else:
        explanation = (
            f"Dates differ by {diff_days} day(s): {d1.isoformat()} vs {d2.isoformat()}. "
            "Note: Dates from different reporting periods or publication timelines are not automatically contradictions."
        )
        status = DateComparisonStatus.DIFFERENT.value

    return {
        "is_matching": is_match,
        "comparison_status": status,
        "date1": d1.isoformat(),
        "date2": d2.isoformat(),
        "difference_days": diff_days,
        "explanation": explanation,
    }


def normalize_reporting_period(period: Any) -> Tuple[Optional[str], Optional[str]]:
    """Normalize a reporting period string into a standard canonical key.
    
    Supports:
    - Quarters: "Q1 2024", "2024-Q1", "2024 Q1" -> "2024-Q1"
    - Fiscal Years: "FY2023", "FY 2023", "2023 FY" -> "FY2023"
    - Years: "2024", 2024 -> "2024"
    - Halves: "H1 2024", "2024-H1" -> "2024-H1"
    
    Args:
        period: Period string or int.
        
    Returns:
        Tuple of (canonical_period, error_message).
    """
    if period is None:
        return None, "Reporting period is missing."

    raw = str(period).strip().upper()
    if not raw:
        return None, "Reporting period string is empty."

    # Quarter match: "Q1 2024", "2024-Q1", "2024 Q1", "Q1-2024"
    q_match1 = re.match(r"^Q([1-4])[-/\s_]?(\d{4})$", raw)
    if q_match1:
        return f"{q_match1.group(2)}-Q{q_match1.group(1)}", None

    q_match2 = re.match(r"^(\d{4})[-/\s_]?Q([1-4])$", raw)
    if q_match2:
        return f"{q_match2.group(1)}-Q{q_match2.group(2)}", None

    # Fiscal Year match: "FY2024", "FY 2024", "2024 FY"
    fy_match1 = re.match(r"^FY[-/\s_]?(\d{4})$", raw)
    if fy_match1:
        return f"FY{fy_match1.group(1)}", None

    fy_match2 = re.match(r"^(\d{4})[-/\s_]?FY$", raw)
    if fy_match2:
        return f"FY{fy_match2.group(1)}", None

    # Half Year match: "H1 2024", "2024-H1"
    h_match1 = re.match(r"^H([1-2])[-/\s_]?(\d{4})$", raw)
    if h_match1:
        return f"{h_match1.group(2)}-H{h_match1.group(1)}", None

    h_match2 = re.match(r"^(\d{4})[-/\s_]?H([1-2])$", raw)
    if h_match2:
        return f"{h_match2.group(1)}-H{h_match2.group(2)}", None

    # Annual Year match: "2024"
    year_match = re.match(r"^(\d{4})$", raw)
    if year_match:
        return year_match.group(1), None

    # Generic cleaned format
    cleaned = re.sub(r"\s+", "-", raw)
    return cleaned, None


def compare_reporting_periods(period1: Any, period2: Any) -> Dict[str, Any]:
    """Compare two reporting periods to determine temporal overlap.
    
    Args:
        period1: First period (e.g. "Q1 2024", "2024").
        period2: Second period (e.g. "2024-Q1", "Q2 2024").
        
    Returns:
        Dictionary with comparison status, normalized periods, and explanation.
    """
    if period1 is None or period2 is None:
        return {
            "is_same_period": False,
            "comparison_status": PeriodComparisonStatus.MISSING.value,
            "period1": None,
            "period2": None,
            "explanation": "One or both reporting periods are missing (None).",
        }

    norm1, err1 = normalize_reporting_period(period1)
    norm2, err2 = normalize_reporting_period(period2)

    if err1 or err2:
        return {
            "is_same_period": False,
            "comparison_status": PeriodComparisonStatus.INVALID.value,
            "period1": str(period1),
            "period2": str(period2),
            "explanation": f"Invalid reporting period format: {err1 or err2}.",
        }

    is_same = norm1 == norm2

    if is_same:
        explanation = f"Reporting periods match: '{norm1}'."
        status = PeriodComparisonStatus.SAME_PERIOD.value
    else:
        explanation = (
            f"Reporting periods differ: '{norm1}' vs '{norm2}'. "
            "Data points from separate reporting periods represent distinct historical intervals, "
            "not an internal contradiction."
        )
        status = PeriodComparisonStatus.DIFFERENT_PERIODS.value

    return {
        "is_same_period": is_same,
        "comparison_status": status,
        "period1": norm1,
        "period2": norm2,
        "explanation": explanation,
    }


# ---------------------------------------------------------------------------
# Structured Evaluation & Report Generation
# ---------------------------------------------------------------------------

def evaluate_consistency(
    evidence_items: Optional[List[Any]] = None,
    claim: Optional[Any] = None,
    structured_data: Optional[List[Dict[str, Any]]] = None,
    tolerance: float = 0.0
) -> Dict[str, Any]:
    """Evaluate structured consistency across evidence items or structured data.
    
    If structured metrics are unavailable, returns explicit INSUFFICIENT status
    with consistency_score = None (does not fabricate natural language inference).
    
    Args:
        evidence_items: Optional list of Evidence models or dictionaries.
        claim: Optional Claim model or dictionary.
        structured_data: Optional list of structured metric dictionaries:
                         [{evidence_id, metric, value, unit, period, date}, ...]
        tolerance: Numeric tolerance for value equivalence.
        
    Returns:
        Dictionary with counts, comparisons, consistency_status, score, and explanation.
    """
    items = structured_data if structured_data is not None else []

    # If structured_data was not explicitly supplied, check metadata in evidence_items
    if not items and evidence_items:
        for ev in evidence_items:
            meta = ev.get("metadata", {}) if isinstance(ev, dict) else getattr(ev, "metadata", {})
            if isinstance(meta, dict) and "structured_data" in meta:
                s_data = meta["structured_data"]
                if isinstance(s_data, list):
                    items.extend(s_data)
                elif isinstance(s_data, dict):
                    items.append(s_data)
            elif isinstance(meta, dict) and "metric_value" in meta:
                items.append({
                    "evidence_id": ev.get("evidence_id") if isinstance(ev, dict) else getattr(ev, "evidence_id", None),
                    "metric": meta.get("metric_name", "general"),
                    "value": meta.get("metric_value"),
                    "unit": meta.get("metric_unit"),
                    "period": meta.get("reporting_period"),
                    "date": meta.get("metric_date"),
                })

    # If still no structured data, return INSUFFICIENT
    if len(items) < 2:
        return {
            "comparison_count": 0,
            "consistent_count": 0,
            "inconsistent_count": 0,
            "unknown_count": 0,
            "consistency_score": None,
            "consistency_status": ConsistencyStatus.INSUFFICIENT.value,
            "comparison_details": [],
            "issues": [
                "Insufficient structured data available for comparison. "
                "At least two structured evidence data points are required."
            ],
            "explanation": (
                "No structured values available for comparison across evidence items. "
                "The Consistency Checker performs structured evaluations and does not "
                "infer ungrounded numbers from raw text snippets."
            ),
        }

    comparison_details: List[Dict[str, Any]] = []
    consistent_count = 0
    inconsistent_count = 0
    unknown_count = 0
    issues: List[str] = []

    # Pairwise comparison across structured items
    for i in range(len(items)):
        for j in range(i + 1, len(items)):
            item1 = items[i]
            item2 = items[j]

            metric1 = item1.get("metric", "general")
            metric2 = item2.get("metric", "general")

            # Only compare if metrics are related
            if metric1 != metric2:
                continue

            period1 = item1.get("period")
            period2 = item2.get("period")
            period_res = compare_reporting_periods(period1, period2)

            # If periods are explicitly different, do NOT treat different values as contradictory
            if period_res["comparison_status"] == PeriodComparisonStatus.DIFFERENT_PERIODS.value:
                comparison_details.append({
                    "item1_id": item1.get("evidence_id"),
                    "item2_id": item2.get("evidence_id"),
                    "metric": metric1,
                    "type": "reporting_period_difference",
                    "period_comparison": period_res,
                    "is_contradiction": False,
                    "note": "Values apply to different reporting periods.",
                })
                continue

            # Compare numeric values
            val1 = item1.get("value")
            val2 = item2.get("value")
            unit1 = item1.get("unit")
            unit2 = item2.get("unit")

            val_res = compare_numeric_values(val1, val2, unit1=unit1, unit2=unit2, tolerance=tolerance)
            status = val_res["comparison_status"]

            detail_entry = {
                "item1_id": item1.get("evidence_id"),
                "item2_id": item2.get("evidence_id"),
                "metric": metric1,
                "type": "numeric_comparison",
                "result": val_res,
            }

            if status == ValueComparisonStatus.CONSISTENT.value:
                consistent_count += 1
            elif status == ValueComparisonStatus.INCONSISTENT.value:
                inconsistent_count += 1
                issues.append(
                    f"Conflict on metric '{metric1}': {val_res['normalized_value1']} vs "
                    f"{val_res['normalized_value2']} {val_res['canonical_unit']}."
                )
            else:
                unknown_count += 1
                issues.append(f"Inconclusive comparison on '{metric1}': {val_res['explanation']}")

            comparison_details.append(detail_entry)

    total_comparisons = consistent_count + inconsistent_count + unknown_count

    if total_comparisons == 0:
        return {
            "comparison_count": 0,
            "consistent_count": 0,
            "inconsistent_count": 0,
            "unknown_count": 0,
            "consistency_score": None,
            "consistency_status": ConsistencyStatus.UNKNOWN.value,
            "comparison_details": comparison_details,
            "issues": ["No matching comparable metrics found between structured items."],
            "explanation": "Structured data was present, but no matching comparable metric pairs were found.",
        }

    # Calculate score over valid comparisons
    valid_count = consistent_count + inconsistent_count
    if valid_count > 0:
        score = round(consistent_count / valid_count, 4)
    else:
        # Only unknown/incompatible units comparisons
        score = None

    if score is not None:
        if score == 1.0:
            overall_status = ConsistencyStatus.CONSISTENT.value
        elif score == 0.0:
            overall_status = ConsistencyStatus.INCONSISTENT.value
        else:
            overall_status = ConsistencyStatus.MIXED.value
    else:
        overall_status = ConsistencyStatus.UNKNOWN.value

    explanation = (
        f"Evaluated {total_comparisons} structured comparison(s): {consistent_count} consistent, "
        f"{inconsistent_count} inconsistent, {unknown_count} inconclusive. "
        f"Consistency score: {score if score is not None else 'N/A'} ({overall_status})."
    )

    return {
        "comparison_count": total_comparisons,
        "consistent_count": consistent_count,
        "inconsistent_count": inconsistent_count,
        "unknown_count": unknown_count,
        "consistency_score": score,
        "consistency_status": overall_status,
        "comparison_details": comparison_details,
        "issues": issues,
        "explanation": explanation,
    }


def generate_consistency_report(
    evidence_items: Optional[List[Any]] = None,
    claim: Optional[Any] = None,
    structured_data: Optional[List[Dict[str, Any]]] = None,
    tolerance: float = 0.0
) -> Dict[str, Any]:
    """Generate a structured diagnostic consistency report for a claim.
    
    Args:
        evidence_items: Optional list of Evidence items.
        claim: Optional Claim item (model or dict).
        structured_data: Optional list of structured metric dictionaries.
        tolerance: Numeric comparison tolerance.
        
    Returns:
        Structured report dictionary.
    """
    eval_res = evaluate_consistency(
        evidence_items=evidence_items,
        claim=claim,
        structured_data=structured_data,
        tolerance=tolerance,
    )

    # Extract claim_id safely
    cid = None
    if isinstance(claim, dict):
        cid = claim.get("claim_id")
    elif claim is not None:
        cid = getattr(claim, "claim_id", None)

    eval_res["claim_id"] = str(cid).strip() if cid else None
    return eval_res


# ---------------------------------------------------------------------------
# Object-Oriented Component Wrapper
# ---------------------------------------------------------------------------

class ConsistencyChecker:
    """Detects numerical, date, and unit conflicts across claims and evidence."""

    def __init__(
        self,
        config: Optional[Dict[str, Any]] = None,
        default_tolerance: float = 0.0
    ):
        """Initialize ConsistencyChecker with optional configuration.
        
        Args:
            config: Optional configuration dictionary.
            default_tolerance: Default numeric tolerance for value comparison.
        """
        self.config = config or {}
        self.default_tolerance = default_tolerance

    def compare_values(
        self,
        value1: Any,
        value2: Any,
        unit1: Optional[str] = None,
        unit2: Optional[str] = None,
        tolerance: Optional[float] = None
    ) -> Dict[str, Any]:
        """Compare two numerical values with unit normalization."""
        tol = tolerance if tolerance is not None else self.default_tolerance
        return compare_numeric_values(value1, value2, unit1=unit1, unit2=unit2, tolerance=tol)

    def compare_dates(self, date1: Any, date2: Any) -> Dict[str, Any]:
        """Compare two dates for temporal equivalence."""
        return compare_dates(date1, date2)

    def compare_reporting_periods(self, period1: Any, period2: Any) -> Dict[str, Any]:
        """Compare two reporting periods."""
        return compare_reporting_periods(period1, period2)

    def evaluate_claim(
        self,
        claim: Optional[Any] = None,
        evidence_items: Optional[List[Any]] = None,
        structured_data: Optional[List[Dict[str, Any]]] = None,
        tolerance: Optional[float] = None
    ) -> Dict[str, Any]:
        """Evaluate consistency for a single claim across its backing evidence."""
        tol = tolerance if tolerance is not None else self.default_tolerance
        return generate_consistency_report(
            evidence_items=evidence_items,
            claim=claim,
            structured_data=structured_data,
            tolerance=tol,
        )

    def evaluate_claims(
        self,
        claims: List[Any],
        evidence_items: Optional[List[Any]] = None,
        structured_data_map: Optional[Dict[str, List[Dict[str, Any]]]] = None,
        tolerance: Optional[float] = None
    ) -> Dict[str, Any]:
        """Evaluate consistency across a batch of claims.
        
        Args:
            claims: List of Claim models or dictionaries.
            evidence_items: Complete list of Evidence items.
            structured_data_map: Optional dictionary mapping claim_id -> structured_data list.
            tolerance: Optional tolerance override.
            
        Returns:
            Batch summary dictionary with total claims, counts, average score, and reports.
        """
        if not claims or not isinstance(claims, list):
            return {
                "total_claims": 0,
                "consistent_claims": 0,
                "inconsistent_claims": 0,
                "insufficient_claims": 0,
                "available_scores_count": 0,
                "average_consistency_score": None,
                "reports": [],
            }

        tol = tolerance if tolerance is not None else self.default_tolerance
        reports: List[Dict[str, Any]] = []
        available_scores: List[float] = []

        consistent_claims = 0
        inconsistent_claims = 0
        insufficient_claims = 0

        for claim in claims:
            cid = claim.get("claim_id") if isinstance(claim, dict) else getattr(claim, "claim_id", None)
            s_data = structured_data_map.get(cid) if structured_data_map and cid else None

            # Filter evidence linked to this claim if evidence_ids exist
            eids = claim.get("evidence_ids", []) if isinstance(claim, dict) else getattr(claim, "evidence_ids", [])
            linked_evidence = None
            if evidence_items and eids:
                linked_evidence = [
                    ev for ev in evidence_items
                    if (ev.get("evidence_id") if isinstance(ev, dict) else getattr(ev, "evidence_id", None)) in eids
                ]

            rep = self.evaluate_claim(
                claim=claim,
                evidence_items=linked_evidence or evidence_items,
                structured_data=s_data,
                tolerance=tol,
            )
            reports.append(rep)

            status = rep["consistency_status"]
            if status == ConsistencyStatus.CONSISTENT.value:
                consistent_claims += 1
            elif status == ConsistencyStatus.INCONSISTENT.value:
                inconsistent_claims += 1
            elif status in (ConsistencyStatus.INSUFFICIENT.value, ConsistencyStatus.UNKNOWN.value):
                insufficient_claims += 1

            if rep["consistency_score"] is not None:
                available_scores.append(rep["consistency_score"])

        avg_score = (
            round(sum(available_scores) / len(available_scores), 4)
            if available_scores
            else None
        )

        return {
            "total_claims": len(reports),
            "consistent_claims": consistent_claims,
            "inconsistent_claims": inconsistent_claims,
            "insufficient_claims": insufficient_claims,
            "available_scores_count": len(available_scores),
            "average_consistency_score": avg_score,
            "reports": reports,
        }

    def check_conflicts(
        self,
        claims: List[Dict[str, Any]],
        evidence: List[Dict[str, Any]],
        verification_results: Optional[List[Dict[str, Any]]] = None
    ) -> Dict[str, Any]:
        """Legacy helper matching Stage 1 placeholder interface."""
        return self.evaluate_claims(claims=claims, evidence_items=evidence)
