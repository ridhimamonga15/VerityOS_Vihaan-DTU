"""Source Reliability Checker Component for VerityOS.

This module evaluates the reliability and credibility characteristics of evidence sources
based purely on the metadata supplied in the evidence packet (such as source URL,
title, source type classification, and completeness).

Architectural Principles:
1. Evaluates metadata only: does NOT perform web searches, network requests, or scraping.
2. Does NOT duplicate semantic claim verification (Member 1's Verification Agent responsibility).
3. Supports both Pydantic `Evidence` models and standard Python dictionaries.
4. Uses transparent, configurable, and explainable categorization and scoring rubrics.
5. Missing or unknown information is handled conservatively without artificial inflation.
6. A syntactically valid URL or recognized domain does NOT guarantee truth or reachability.
"""

from enum import Enum
import re
from typing import Any, Dict, List, Optional, Tuple, Union
from urllib.parse import urlparse


# ---------------------------------------------------------------------------
# Enums and Constants
# ---------------------------------------------------------------------------

class SourceCategory(str, Enum):
    """Recognized source classification categories."""
    GOVERNMENT_OFFICIAL = "GOVERNMENT_OFFICIAL"
    ACADEMIC_RESEARCH = "ACADEMIC_RESEARCH"
    REPUTABLE_NEWS = "REPUTABLE_NEWS"
    ORGANIZATIONAL_INSTITUTIONAL = "ORGANIZATIONAL_INSTITUTIONAL"
    GENERAL_WEBSITE = "GENERAL_WEBSITE"
    UNKNOWN = "UNKNOWN"


class ReliabilityLevel(str, Enum):
    """Qualitative reliability levels based on normalized scores."""
    HIGH = "HIGH"       # score >= 0.75
    MEDIUM = "MEDIUM"   # 0.45 <= score < 0.75
    LOW = "LOW"         # 0.20 <= score < 0.45
    UNKNOWN = "UNKNOWN" # score < 0.20 or missing vital metadata


# Baseline reliability scores per category (configurable)
DEFAULT_CATEGORY_SCORES: Dict[str, float] = {
    SourceCategory.GOVERNMENT_OFFICIAL.value: 0.85,
    SourceCategory.ACADEMIC_RESEARCH.value: 0.85,
    SourceCategory.REPUTABLE_NEWS.value: 0.75,
    SourceCategory.ORGANIZATIONAL_INSTITUTIONAL.value: 0.65,
    SourceCategory.GENERAL_WEBSITE.value: 0.45,
    SourceCategory.UNKNOWN.value: 0.20,
}

# Known reputable news domains (illustrative, non-exhaustive)
KNOWN_NEWS_DOMAINS = {
    "reuters.com", "bbc.com", "bbc.co.uk", "apnews.com",
    "nytimes.com", "wsj.com", "bloomberg.com", "theguardian.com",
    "nature.com", "science.org", "ft.com", "economist.com",
}


# ---------------------------------------------------------------------------
# Helper Extraction & Validation Functions
# ---------------------------------------------------------------------------

def extract_evidence_fields(evidence: Any) -> Dict[str, Any]:
    """Extract standard evidence fields from either a Pydantic model or dictionary.
    
    Args:
        evidence: Pydantic Evidence instance or Python dictionary.
        
    Returns:
        Dictionary with extracted fields: evidence_id, source_url, source_title,
        source_type, snippet, and metadata.
    """
    if evidence is None:
        return {
            "evidence_id": None,
            "source_url": None,
            "source_title": None,
            "source_type": None,
            "snippet": None,
            "metadata": {},
        }

    if isinstance(evidence, dict):
        return {
            "evidence_id": evidence.get("evidence_id"),
            "source_url": evidence.get("source_url"),
            "source_title": evidence.get("source_title"),
            "source_type": evidence.get("source_type"),
            "snippet": evidence.get("snippet"),
            "metadata": evidence.get("metadata", {}),
        }

    # Pydantic or duck-typed object
    return {
        "evidence_id": getattr(evidence, "evidence_id", None),
        "source_url": getattr(evidence, "source_url", None),
        "source_title": getattr(evidence, "source_title", None),
        "source_type": getattr(evidence, "source_type", None),
        "snippet": getattr(evidence, "snippet", None),
        "metadata": getattr(evidence, "metadata", {}),
    }


def is_valid_url_format(url: Optional[str]) -> bool:
    """Check if a string possesses a syntactically valid HTTP/HTTPS URL format.
    
    Important Note:
    A valid URL format does NOT imply that the target server is reachable,
    currently online, or factually accurate.
    
    Args:
        url: URL string to test.
        
    Returns:
        True if the URL has a valid scheme and domain format, False otherwise.
    """
    if not isinstance(url, str):
        return False
    stripped = url.strip()
    if not stripped:
        return False
    try:
        parsed = urlparse(stripped)
        return bool(
            parsed.scheme in ("http", "https")
            and parsed.netloc
            and "." in parsed.netloc
            and not parsed.netloc.startswith(".")
            and not parsed.netloc.endswith(".")
        )
    except Exception:
        return False


def validate_source_metadata(evidence: Any) -> Dict[str, Any]:
    """Validate completeness and formatting of source metadata.
    
    Examines:
    - Evidence ID presence
    - Source URL presence and basic syntax
    - Source title presence and length
    - Source type presence
    - Overall metadata completeness ratio
    
    Args:
        evidence: Evidence item (Pydantic model or dictionary).
        
    Returns:
        Dictionary containing is_valid, extracted fields, issues list,
        and metadata_completeness score (0.0 to 1.0).
    """
    fields = extract_evidence_fields(evidence)
    issues: List[str] = []

    # Check Evidence ID
    eid = fields.get("evidence_id")
    if not eid or not str(eid).strip():
        issues.append("Missing or empty 'evidence_id'.")

    # Check Source URL
    url = fields.get("source_url")
    if not url or not str(url).strip():
        issues.append("Missing 'source_url'.")
    elif not is_valid_url_format(url):
        issues.append(f"Invalid URL format: '{url}'. Expected valid http:// or https:// URL.")

    # Check Source Title
    title = fields.get("source_title")
    if not title or not str(title).strip():
        issues.append("Missing or empty 'source_title'.")

    # Check Source Type
    stype = fields.get("source_type")
    if not stype or not str(stype).strip():
        issues.append("Missing or empty 'source_type'.")

    # Calculate metadata completeness across 5 key fields:
    # evidence_id, source_url, source_title, source_type, snippet
    core_keys = ["evidence_id", "source_url", "source_title", "source_type", "snippet"]
    present_count = sum(
        1 for k in core_keys
        if fields.get(k) is not None and str(fields.get(k)).strip() != ""
    )
    metadata_completeness = round(present_count / len(core_keys), 2)

    # Basic validity: at least evidence_id or one identifier is present
    is_valid = bool(eid and str(eid).strip())

    return {
        "is_valid": is_valid,
        "evidence_id": eid,
        "source_url": url,
        "source_title": title,
        "source_type": stype,
        "snippet": fields.get("snippet"),
        "issues": issues,
        "metadata_completeness": metadata_completeness,
    }


# ---------------------------------------------------------------------------
# Classification Function
# ---------------------------------------------------------------------------

def classify_source_type(
    source_type: Optional[str],
    source_url: Optional[str] = None
) -> str:
    """Classify the evidence source into a transparent, explainable category.
    
    Classification priority:
    1. Direct URL top-level domain / domain inspection (e.g. .gov, .edu, known news).
    2. Stated source_type keyword matching (e.g. "government", "academic", "news").
    3. Fallback to GENERAL_WEBSITE if URL exists, or UNKNOWN.
    
    Category definitions:
    - GOVERNMENT_OFFICIAL: Official state, federal, or regulatory portals (.gov, .mil).
    - ACADEMIC_RESEARCH: Universities, research labs, and academic repositories (.edu, .ac.uk, arxiv, doi).
    - REPUTABLE_NEWS: Major journalism and press agencies (reuters, bbc, apnews, or type='news').
    - ORGANIZATIONAL_INSTITUTIONAL: International organizations, standards bodies, NGOs (.org, .int).
    - GENERAL_WEBSITE: Commercial or general web publications (.com, .net, type='website').
    - UNKNOWN: Missing, invalid, or unclassifiable source metadata.
    
    Args:
        source_type: Optional string indicating the type (e.g. "website", "academic").
        source_url: Optional string URL of the source.
        
    Returns:
        One of the SourceCategory enum values as a string.
    """
    norm_type = str(source_type).strip().lower() if source_type else ""
    norm_url = str(source_url).strip().lower() if source_url else ""

    netloc = ""
    if norm_url:
        try:
            parsed = urlparse(norm_url)
            netloc = parsed.netloc.lower()
        except Exception:
            netloc = ""

    # 1. Government / Official checks
    if any(netloc.endswith(tld) for tld in (".gov", ".mil", ".gov.uk", ".gov.in", ".gov.au")):
        return SourceCategory.GOVERNMENT_OFFICIAL.value
    if any(k in norm_type for k in ("government", "gov", "official", "regulatory", "federal")):
        return SourceCategory.GOVERNMENT_OFFICIAL.value

    # 2. Academic / Research checks
    if any(netloc.endswith(tld) for tld in (".edu", ".ac.uk", ".edu.in", ".edu.au")):
        return SourceCategory.ACADEMIC_RESEARCH.value
    if any(d in netloc for d in ("arxiv.org", "doi.org", "researchgate.net", "biorxiv.org", "pubmed")):
        return SourceCategory.ACADEMIC_RESEARCH.value
    if any(k in norm_type for k in ("academic", "research", "journal", "university", "paper", "study", "peer_reviewed")):
        return SourceCategory.ACADEMIC_RESEARCH.value

    # 3. Reputable News checks
    if any(d in netloc for d in KNOWN_NEWS_DOMAINS):
        return SourceCategory.REPUTABLE_NEWS.value
    if any(k in norm_type for k in ("news", "journalism", "press", "media", "newspaper", "broadcast")):
        return SourceCategory.REPUTABLE_NEWS.value

    # 4. Organizational / Institutional checks
    if any(netloc.endswith(tld) for tld in (".org", ".int")):
        return SourceCategory.ORGANIZATIONAL_INSTITUTIONAL.value
    if any(k in norm_type for k in ("organization", "institution", "ngo", "nonprofit", "foundation")):
        return SourceCategory.ORGANIZATIONAL_INSTITUTIONAL.value

    # 5. General Website checks
    if any(k in norm_type for k in ("website", "web", "blog", "online", "portal", "forum")):
        return SourceCategory.GENERAL_WEBSITE.value
    if netloc:
        return SourceCategory.GENERAL_WEBSITE.value

    # 6. Default to UNKNOWN
    return SourceCategory.UNKNOWN.value


# ---------------------------------------------------------------------------
# Scoring Function
# ---------------------------------------------------------------------------

def calculate_source_reliability(
    evidence: Any,
    config: Optional[Dict[str, Any]] = None
) -> float:
    """Calculate an explainable, normalized reliability score between 0.0 and 1.0.
    
    Rubric:
    1. Base Category Score (0.20 - 0.85):
       - Government: 0.85
       - Academic: 0.85
       - Reputable News: 0.75
       - Organization: 0.65
       - General Website: 0.45
       - Unknown: 0.20
    2. Completeness Adjustment:
       - Scales base score proportionally: base_score * (0.60 + 0.40 * completeness).
    3. Metadata Penalties and Bonuses:
       - Missing or invalid URL: -0.15 penalty.
       - Secure HTTPS protocol: +0.05 bonus.
       - Meaningful Title (length >= 5): +0.05 bonus; Missing title: -0.05 penalty.
       - Missing Evidence ID: -0.20 penalty.
    4. Boundary Clamp:
       - Final score is strictly bounded in [0.0, 1.0].
       
    Args:
        evidence: Evidence item (Pydantic model or dictionary).
        config: Optional configuration dictionary overriding category scores.
        
    Returns:
        Float reliability score normalized between 0.0 and 1.0.
    """
    category_scores = (config or {}).get("category_scores", DEFAULT_CATEGORY_SCORES)
    validation = validate_source_metadata(evidence)

    # Empty or completely invalid payload gets baseline 0.0
    if not validation["is_valid"] and validation["metadata_completeness"] == 0.0:
        return 0.0

    category = classify_source_type(validation["source_type"], validation["source_url"])
    base_score = category_scores.get(category, 0.20)

    # Scale with metadata completeness
    completeness = validation["metadata_completeness"]
    score = base_score * (0.60 + 0.40 * completeness)

    # URL adjustments
    url = validation["source_url"]
    if not url:
        score -= 0.10
    elif not is_valid_url_format(url):
        score -= 0.15
    elif url.strip().lower().startswith("https://"):
        score += 0.05

    # Title adjustments
    title = validation["source_title"]
    if title and len(str(title).strip()) >= 5:
        score += 0.05
    else:
        score -= 0.05

    # Missing ID penalty
    if not validation["evidence_id"]:
        score -= 0.20

    # Strict normalization [0.0, 1.0]
    normalized_score = max(0.0, min(1.0, round(score, 4)))
    return normalized_score


def determine_reliability_level(score: float, issues: Optional[List[str]] = None) -> str:
    """Map a numerical reliability score to a qualitative reliability level.
    
    Levels:
    - HIGH:    Score >= 0.75
    - MEDIUM:  0.45 <= Score < 0.75
    - LOW:     0.20 <= Score < 0.45
    - UNKNOWN: Score < 0.20 or severe lack of metadata
    
    Args:
        score: Normalized reliability score.
        issues: Optional list of identified validation issues.
        
    Returns:
        ReliabilityLevel string.
    """
    if score >= 0.75:
        return ReliabilityLevel.HIGH.value
    elif score >= 0.45:
        return ReliabilityLevel.MEDIUM.value
    elif score >= 0.20:
        return ReliabilityLevel.LOW.value
    else:
        return ReliabilityLevel.UNKNOWN.value


# ---------------------------------------------------------------------------
# Reporting Function
# ---------------------------------------------------------------------------

def generate_source_report(
    evidence: Any,
    config: Optional[Dict[str, Any]] = None
) -> Dict[str, Any]:
    """Generate a structured diagnostic reliability report for an evidence item.
    
    Args:
        evidence: Evidence item (Pydantic model or dictionary).
        config: Optional configuration dictionary.
        
    Returns:
        Dictionary containing:
        - evidence_id: str
        - source_type: Optional[str]
        - source_category: str
        - reliability_score: float (0.0 to 1.0)
        - reliability_level: str (HIGH, MEDIUM, LOW, UNKNOWN)
        - metadata_completeness: float (0.0 to 1.0)
        - issues: List[str]
        - explanation: str
    """
    validation = validate_source_metadata(evidence)
    category = classify_source_type(validation["source_type"], validation["source_url"])
    score = calculate_source_reliability(evidence, config=config)
    level = determine_reliability_level(score, validation["issues"])

    # Human-readable explanation
    eid_str = validation["evidence_id"] or "unidentified"
    if validation["issues"]:
        issue_summary = "; ".join(validation["issues"])
        explanation = (
            f"Evidence '{eid_str}' classified as {category} with reliability score {score:.2f} ({level}). "
            f"Issues noted: {issue_summary}."
        )
    else:
        explanation = (
            f"Evidence '{eid_str}' classified as {category} with complete metadata and "
            f"reliability score {score:.2f} ({level})."
        )

    return {
        "evidence_id": validation["evidence_id"] or "unknown",
        "source_type": validation["source_type"],
        "source_category": category,
        "reliability_score": score,
        "reliability_level": level,
        "metadata_completeness": validation["metadata_completeness"],
        "issues": validation["issues"],
        "explanation": explanation,
    }


# ---------------------------------------------------------------------------
# Object-Oriented Component Wrapper
# ---------------------------------------------------------------------------

class SourceChecker:
    """Evaluates the reliability and credibility characteristics of evidence sources.
    
    Provides single-item and batch evaluation methods for the Trust Engine coordinator.
    """

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """Initialize SourceChecker with optional configuration.
        
        Args:
            config: Optional dictionary containing custom category_scores.
        """
        self.config = config or {}

    def evaluate_source(self, evidence: Any) -> Dict[str, Any]:
        """Evaluate a single evidence item and return a structured report.
        
        Args:
            evidence: Pydantic Evidence instance or dictionary.
            
        Returns:
            Diagnostic source reliability report dictionary.
        """
        return generate_source_report(evidence, config=self.config)

    def assess_source(self, evidence: Any) -> Dict[str, Any]:
        """Alias for evaluate_source for backward compatibility."""
        return self.evaluate_source(evidence)

    def evaluate_sources(self, evidence_list: List[Any]) -> Dict[str, Any]:
        """Evaluate a batch of evidence items and return an aggregated summary.
        
        Args:
            evidence_list: List of Evidence objects or dictionaries.
            
        Returns:
            Dictionary containing:
            - total_sources: int
            - average_reliability_score: float
            - reliability_distribution: Dict[str, int] (counts of HIGH, MEDIUM, LOW, UNKNOWN)
            - summary_level: str (overall qualitative grade)
            - source_reports: List of individual source reports
        """
        if not evidence_list or not isinstance(evidence_list, list):
            return {
                "total_sources": 0,
                "average_reliability_score": 0.0,
                "reliability_distribution": {
                    ReliabilityLevel.HIGH.value: 0,
                    ReliabilityLevel.MEDIUM.value: 0,
                    ReliabilityLevel.LOW.value: 0,
                    ReliabilityLevel.UNKNOWN.value: 0,
                },
                "summary_level": ReliabilityLevel.UNKNOWN.value,
                "source_reports": [],
            }

        reports: List[Dict[str, Any]] = []
        scores: List[float] = []
        distribution = {
            ReliabilityLevel.HIGH.value: 0,
            ReliabilityLevel.MEDIUM.value: 0,
            ReliabilityLevel.LOW.value: 0,
            ReliabilityLevel.UNKNOWN.value: 0,
        }

        for ev in evidence_list:
            rep = self.evaluate_source(ev)
            reports.append(rep)
            scores.append(rep["reliability_score"])
            level = rep["reliability_level"]
            distribution[level] = distribution.get(level, 0) + 1

        avg_score = round(sum(scores) / len(scores), 4) if scores else 0.0
        summary_level = determine_reliability_level(avg_score)

        return {
            "total_sources": len(reports),
            "average_reliability_score": avg_score,
            "reliability_distribution": distribution,
            "summary_level": summary_level,
            "source_reports": reports,
        }
