"""Data schemas and validation models for the VerityOS Trust Engine.

Implements the official integration contract agreed upon with Member 1.
Defines Pydantic models for:
- Claim
- Evidence
- VerificationResult
- TrustEngineDataPayload
- TrustEngineInput (the complete common envelope)
- Output schemas for trust evaluation results

Provides strict validation with friendly error messages while safely handling
optional metadata and preserving forward compatibility.
"""

from enum import Enum
from typing import Any, Dict, List, Optional

try:
    from pydantic import BaseModel, Field, field_validator, ConfigDict
    PYDANTIC_V2 = True
except ImportError:
    try:
        from pydantic import BaseModel, Field, validator
        ConfigDict = None
        PYDANTIC_V2 = False
    except ImportError:
        # Graceful fallback if pydantic is not yet installed in the environment
        BaseModel = object
        Field = lambda default=None, **kwargs: default
        field_validator = None
        validator = None
        ConfigDict = None
        PYDANTIC_V2 = None


# ---------------------------------------------------------------------------
# Verification Status Enum
# ---------------------------------------------------------------------------

class VerificationStatus(str, Enum):
    """Allowed verification statuses produced by Member 1's Verification Agent."""
    SUPPORTED = "SUPPORTED"
    CONTRADICTED = "CONTRADICTED"
    INSUFFICIENT = "INSUFFICIENT"


# ---------------------------------------------------------------------------
# Core Input Models
# ---------------------------------------------------------------------------

if PYDANTIC_V2 is not None:

    class Claim(BaseModel):
        """Represents an individual factual claim extracted by Member 1."""
        if ConfigDict is not None:
            model_config = ConfigDict(extra="allow", populate_by_name=True)
        else:
            class Config:
                extra = "allow"

        claim_id: str = Field(
            ...,
            description="Unique identifier for the claim (e.g. 'C1')."
        )
        claim_text: str = Field(
            ...,
            description="The textual statement or assertion of the claim."
        )
        evidence_ids: List[str] = Field(
            default_factory=list,
            description="IDs of evidence items linked to this claim."
        )
        metadata: Optional[Dict[str, Any]] = Field(
            default_factory=dict,
            description="Optional metadata such as timestamps, source categories, etc."
        )

        if PYDANTIC_V2:
            @field_validator("claim_id", "claim_text")
            @classmethod
            def check_not_empty(cls, value: str, info) -> str:
                if not value or not value.strip():
                    raise ValueError(f"Field '{info.field_name}' cannot be empty or whitespace.")
                return value.strip()
        else:
            @validator("claim_id", "claim_text")
            def check_not_empty(cls, value, field):
                if not value or not str(value).strip():
                    raise ValueError(f"Field '{field.name}' cannot be empty or whitespace.")
                return str(value).strip()


    class Evidence(BaseModel):
        """Represents an individual piece of evidence supporting or refuting a claim."""
        if ConfigDict is not None:
            model_config = ConfigDict(extra="allow", populate_by_name=True)
        else:
            class Config:
                extra = "allow"

        evidence_id: str = Field(
            ...,
            description="Unique identifier for the evidence item (e.g. 'E1')."
        )
        source_url: Optional[str] = Field(
            default=None,
            description="URL of the evidence source if applicable."
        )
        source_title: Optional[str] = Field(
            default=None,
            description="Human-readable title or headline of the source."
        )
        snippet: Optional[str] = Field(
            default=None,
            description="Excerpt or snippet of raw content used as evidence."
        )
        source_type: Optional[str] = Field(
            default=None,
            description="Classification of the source (e.g. 'website', 'document', 'news')."
        )
        publication_date: Optional[str] = Field(
            default=None,
            description="ISO-formatted publication or last-modified timestamp."
        )
        sha256_hash: Optional[str] = Field(
            default=None,
            description="Cryptographic SHA-256 hash of the evidence file/content."
        )
        metadata: Optional[Dict[str, Any]] = Field(
            default_factory=dict,
            description="Additional optional metadata."
        )

        if PYDANTIC_V2:
            @field_validator("evidence_id")
            @classmethod
            def check_evidence_id(cls, value: str) -> str:
                if not value or not value.strip():
                    raise ValueError("Field 'evidence_id' cannot be empty or whitespace.")
                return value.strip()
        else:
            @validator("evidence_id")
            def check_evidence_id(cls, value):
                if not value or not str(value).strip():
                    raise ValueError("Field 'evidence_id' cannot be empty or whitespace.")
                return str(value).strip()


    class VerificationResult(BaseModel):
        """Represents the semantic claim-verification outcome from Member 1."""
        if ConfigDict is not None:
            model_config = ConfigDict(extra="allow", use_enum_values=True)
        else:
            class Config:
                extra = "allow"
                use_enum_values = True

        claim_id: str = Field(
            ...,
            description="Identifier of the claim being verified (e.g. 'C1')."
        )
        status: VerificationStatus = Field(
            ...,
            description="Outcome status: SUPPORTED, CONTRADICTED, or INSUFFICIENT."
        )
        supporting_evidence_ids: List[str] = Field(
            default_factory=list,
            description="Evidence IDs confirming or backing the claim."
        )
        contradicting_evidence_ids: List[str] = Field(
            default_factory=list,
            description="Evidence IDs refuting or conflicting with the claim."
        )
        explanation: Optional[str] = Field(
            default=None,
            description="Human-readable explanation of why the status was assigned."
        )

        if PYDANTIC_V2:
            @field_validator("status", mode="before")
            @classmethod
            def normalize_status(cls, value: Any) -> Any:
                if isinstance(value, str):
                    normalized = value.strip().upper()
                    valid_values = {s.value for s in VerificationStatus}
                    if normalized not in valid_values:
                        raise ValueError(
                            f"Invalid verification status '{value}'. "
                            f"Allowed values are: {sorted(list(valid_values))}."
                        )
                    return normalized
                return value
        else:
            @validator("status", pre=True)
            def normalize_status(cls, value):
                if isinstance(value, str):
                    normalized = value.strip().upper()
                    valid_values = {s.value for s in VerificationStatus}
                    if normalized not in valid_values:
                        raise ValueError(
                            f"Invalid verification status '{value}'. "
                            f"Allowed values are: {sorted(list(valid_values))}."
                        )
                    return normalized
                return value


    class TrustEngineDataPayload(BaseModel):
        """Container for claims, evidence, and verification results nested in 'data'."""
        if ConfigDict is not None:
            model_config = ConfigDict(extra="allow")
        else:
            class Config:
                extra = "allow"

        claims: List[Claim] = Field(
            default_factory=list,
            description="List of factual claims."
        )
        evidence: List[Evidence] = Field(
            default_factory=list,
            description="List of gathered evidence items."
        )
        verification_results: List[VerificationResult] = Field(
            default_factory=list,
            description="List of verification findings from Member 1's Verification Agent."
        )


    class TrustEngineInput(BaseModel):
        """The complete common envelope received by the Trust Engine."""
        if ConfigDict is not None:
            model_config = ConfigDict(extra="allow")
        else:
            class Config:
                extra = "allow"

        task_id: str = Field(
            ...,
            description="Unique identifier for the task (e.g. 'task_001')."
        )
        status: str = Field(
            default="success",
            description="Status of the envelope payload (e.g. 'success')."
        )
        agent: str = Field(
            default="orchestrator",
            description="Name of the producing agent or system component."
        )
        data: TrustEngineDataPayload = Field(
            ...,
            description="Payload containing claims, evidence, and verification results."
        )
        error: Optional[str] = Field(
            default=None,
            description="Error message if the preceding pipeline encountered an issue, else None."
        )

        if PYDANTIC_V2:
            @field_validator("task_id")
            @classmethod
            def check_task_id(cls, value: str) -> str:
                if not value or not value.strip():
                    raise ValueError("Field 'task_id' cannot be empty or whitespace.")
                return value.strip()
        else:
            @validator("task_id")
            def check_task_id(cls, value):
                if not value or not str(value).strip():
                    raise ValueError("Field 'task_id' cannot be empty or whitespace.")
                return str(value).strip()

        @classmethod
        def from_dict(cls, payload: Dict[str, Any]) -> "TrustEngineInput":
            """Safely creates a TrustEngineInput instance.
            
            Handles both the complete envelope format and legacy flat verification packets.
            """
            if not isinstance(payload, dict):
                raise ValueError(f"Input payload must be a dictionary, got {type(payload).__name__}.")

            # If payload is already an envelope with 'data'
            if "data" in payload and isinstance(payload["data"], dict):
                return cls(**payload)

            # If payload is a flat packet (claims, evidence, verification_results at root)
            task_id = payload.get("task_id", "task_unknown")
            status = payload.get("status", "success")
            agent = payload.get("agent", "orchestrator")
            error = payload.get("error", None)

            data_payload = {
                "claims": payload.get("claims", []),
                "evidence": payload.get("evidence", []),
                "verification_results": payload.get("verification_results", []),
            }

            return cls(
                task_id=task_id,
                status=status,
                agent=agent,
                data=TrustEngineDataPayload(**data_payload),
                error=error,
            )

else:
    # Lightweight pure-Python fallback classes if pydantic is not installed
    class Claim:
        def __init__(self, claim_id: str, claim_text: str, evidence_ids: List[str] = None, **kwargs):
            if not claim_id or not str(claim_id).strip():
                raise ValueError("Field 'claim_id' cannot be empty or whitespace.")
            if not claim_text or not str(claim_text).strip():
                raise ValueError("Field 'claim_text' cannot be empty or whitespace.")
            self.claim_id = str(claim_id).strip()
            self.claim_text = str(claim_text).strip()
            self.evidence_ids = evidence_ids or []
            self.metadata = kwargs

    class Evidence:
        def __init__(self, evidence_id: str, source_url: str = None, source_title: str = None,
                     snippet: str = None, source_type: str = None, publication_date: str = None,
                     sha256_hash: str = None, **kwargs):
            if not evidence_id or not str(evidence_id).strip():
                raise ValueError("Field 'evidence_id' cannot be empty or whitespace.")
            self.evidence_id = str(evidence_id).strip()
            self.source_url = source_url
            self.source_title = source_title
            self.snippet = snippet
            self.source_type = source_type
            self.publication_date = publication_date
            self.sha256_hash = sha256_hash
            self.metadata = kwargs

    class VerificationResult:
        def __init__(self, claim_id: str, status: str, supporting_evidence_ids: List[str] = None,
                     contradicting_evidence_ids: List[str] = None, explanation: str = None, **kwargs):
            self.claim_id = str(claim_id).strip()
            norm = str(status).strip().upper()
            valid = {s.value for s in VerificationStatus}
            if norm not in valid:
                raise ValueError(f"Invalid verification status '{status}'. Allowed values are: {sorted(list(valid))}.")
            self.status = norm
            self.supporting_evidence_ids = supporting_evidence_ids or []
            self.contradicting_evidence_ids = contradicting_evidence_ids or []
            self.explanation = explanation
            self.metadata = kwargs

    class TrustEngineDataPayload:
        def __init__(self, claims: List[Any] = None, evidence: List[Any] = None,
                     verification_results: List[Any] = None, **kwargs):
            self.claims = [c if isinstance(c, Claim) else Claim(**c) for c in (claims or [])]
            self.evidence = [e if isinstance(e, Evidence) else Evidence(**e) for e in (evidence or [])]
            self.verification_results = [v if isinstance(v, VerificationResult) else VerificationResult(**v)
                                         for v in (verification_results or [])]

    class TrustEngineInput:
        def __init__(self, task_id: str, status: str = "success", agent: str = "orchestrator",
                     data: Any = None, error: str = None, **kwargs):
            if not task_id or not str(task_id).strip():
                raise ValueError("Field 'task_id' cannot be empty or whitespace.")
            self.task_id = str(task_id).strip()
            self.status = status
            self.agent = agent
            if isinstance(data, dict):
                self.data = TrustEngineDataPayload(**data)
            elif isinstance(data, TrustEngineDataPayload):
                self.data = data
            else:
                self.data = TrustEngineDataPayload()
            self.error = error

        @classmethod
        def from_dict(cls, payload: Dict[str, Any]) -> "TrustEngineInput":
            if not isinstance(payload, dict):
                raise ValueError(f"Input payload must be a dictionary, got {type(payload).__name__}.")
            if "data" in payload and isinstance(payload["data"], dict):
                return cls(**payload)
            return cls(
                task_id=payload.get("task_id", "task_unknown"),
                status=payload.get("status", "success"),
                agent=payload.get("agent", "orchestrator"),
                data=TrustEngineDataPayload(
                    claims=payload.get("claims", []),
                    evidence=payload.get("evidence", []),
                    verification_results=payload.get("verification_results", []),
                ),
                error=payload.get("error", None),
            )


# ---------------------------------------------------------------------------
# Output Schemas (Agreed Response Envelope)
# ---------------------------------------------------------------------------

if PYDANTIC_V2 is not None:
    class DimensionScore(BaseModel):
        """Represents a score for an individual trust dimension."""
        dimension: str
        weight: float
        score: Optional[float] = None
        available: bool = True
        reason: str = ""

    class ClaimEvaluation(BaseModel):
        """Detailed evaluation result for a single claim."""
        claim_id: Optional[str] = None
        claim_text: Optional[str] = None
        trust_score: float = 0.0
        trust_grade: str = "LOW"
        dimension_scores: Dict[str, Any] = Field(default_factory=dict)
        flags: List[str] = Field(default_factory=list)

    class TrustEngineData(BaseModel):
        """Payload data containing overall trust scores and policy decisions."""
        overall_trust_score: float = Field(0.0, ge=0.0, le=1.0, description="Normalized score [0.0, 1.0].")
        trust_grade: str = Field("LOW", description="Qualitative grade: HIGH, MEDIUM, or LOW.")
        policy_decision: str = Field("REJECT", description="Governance outcome: PASS, REVIEW, or REJECT.")
        claim_evaluations: List[ClaimEvaluation] = Field(
            default_factory=list,
            description="Detailed evaluation per claim."
        )

    class TrustEngineResponse(BaseModel):
        """Standardized output response returned by evaluate_trust_engine()."""
        task_id: str
        status: str = "success"
        agent: str = "trust_engine"
        data: TrustEngineData
        error: Optional[str] = None

else:
    class DimensionScore:
        def __init__(self, dimension: str, weight: float, score: float = None,
                     available: bool = True, reason: str = ""):
            self.dimension = dimension
            self.weight = weight
            self.score = score
            self.available = available
            self.reason = reason

    class ClaimEvaluation:
        def __init__(self, claim_id: str = None, claim_text: str = None,
                     trust_score: float = 0.0, trust_grade: str = "LOW",
                     dimension_scores: Dict[str, Any] = None, flags: List[str] = None):
            self.claim_id = claim_id
            self.claim_text = claim_text
            self.trust_score = trust_score
            self.trust_grade = trust_grade
            self.dimension_scores = dimension_scores or {}
            self.flags = flags or []

    class TrustEngineData:
        def __init__(self, overall_trust_score: float = 0.0, trust_grade: str = "LOW",
                     policy_decision: str = "REJECT", claim_evaluations: List[Any] = None):
            self.overall_trust_score = overall_trust_score
            self.trust_grade = trust_grade
            self.policy_decision = policy_decision
            self.claim_evaluations = claim_evaluations or []

    class TrustEngineResponse:
        def __init__(self, task_id: str, status: str = "success", agent: str = "trust_engine",
                     data: Any = None, error: str = None):
            self.task_id = task_id
            self.status = status
            self.agent = agent
            self.data = data or TrustEngineData()
            self.error = error


# Backward compatibility alias
VerificationPacket = TrustEngineInput
