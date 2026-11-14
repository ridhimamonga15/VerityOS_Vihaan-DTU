"""
Pydantic response models — Member 3.

All field names are taken from the agreed blueprint schemas.
The backend serialises whatever the pipeline returns — it does NOT
invent or drop fields.  These models document the *expected* shape
so that FastAPI can generate OpenAPI docs and Member 4 has a contract.
"""

from pydantic import BaseModel, Field
from typing import Any, Optional


# ------------------------------------------------------------------
# Nested models (match blueprint schemas exactly)
# ------------------------------------------------------------------

class EvidenceOut(BaseModel):
    """Single evidence record — blueprint Section 3.2."""
    evidence_id: str
    source_url: str
    source_title: str
    snippet: str
    source_type: str
    published_at: Optional[str] = None
    retrieved_at: str


class ClaimOut(BaseModel):
    """Claim with inline verification info for the API consumer."""
    claim_id: str
    claim_text: str
    evidence_ids: list[str] = []
    verification_status: Optional[str] = None
    supporting_evidence_ids: list[str] = []
    contradicting_evidence_ids: list[str] = []
    explanation: Optional[str] = None


class VerificationResultOut(BaseModel):
    """Per-claim verification result — blueprint Section 3.4."""
    claim_id: str
    status: str  # SUPPORTED | CONTRADICTED | INSUFFICIENT
    supporting_evidence_ids: list[str] = []
    contradicting_evidence_ids: list[str] = []
    explanation: str = ""


class TrustEvaluationOut(BaseModel):
    """
    Trust Engine result container.

    Exact inner fields depend on Member 2's evaluate_trust_engine() return
    schema.  We keep this flexible with Optional + Any so the backend
    never drops unknown trust fields.
    """
    overall_score: Optional[float] = None
    grade: Optional[str] = None
    policy_decision: Optional[str] = None   # PASS | REVIEW | REJECT
    dimension_scores: Optional[dict[str, Any]] = None
    per_claim_evaluations: Optional[list[dict[str, Any]]] = None


class ProvenanceOut(BaseModel):
    """Pipeline provenance / audit metadata."""
    pipeline_stages: list[str] = []
    timestamps: Optional[dict[str, Any]] = None
    mock_mode: bool = False


# ------------------------------------------------------------------
# Top-level responses
# ------------------------------------------------------------------

class HealthResponse(BaseModel):
    """GET /api/health response."""
    status: str = "healthy"
    service: str = "verityos-backend"
    version: str = "0.1.0"


class AnalyzeResponse(BaseModel):
    """
    POST /api/analyze — success response.

    Contains the full pipeline result: decision, trust score, claims,
    evidence, verification results, trust evaluation, provenance,
    limitations and errors.
    """
    task_id: str
    status: str                                         # SUCCESS | ERROR
    query: str
    decision: Optional[str] = None                      # APPROVED | QUARANTINED | REJECTED | INSUFFICIENT_DATA
    trust_score: Optional[float] = None
    trust_grade: Optional[str] = None
    claims: list[ClaimOut] = []
    evidence: list[EvidenceOut] = []
    verification_results: list[VerificationResultOut] = []
    trust_evaluation: Optional[TrustEvaluationOut] = None
    provenance: Optional[ProvenanceOut] = None
    limitations: list[str] = []
    errors: list[str] = []


class ErrorResponse(BaseModel):
    """
    POST /api/analyze — error response (pipeline failure).

    Returns the same top-level shape as AnalyzeResponse so the frontend
    can handle it with a single type.
    """
    task_id: str
    status: str = "ERROR"
    query: str = ""
    decision: Optional[str] = None
    trust_score: Optional[float] = None
    trust_grade: Optional[str] = None
    claims: list[ClaimOut] = []
    evidence: list[EvidenceOut] = []
    verification_results: list[VerificationResultOut] = []
    trust_evaluation: Optional[TrustEvaluationOut] = None
    provenance: Optional[ProvenanceOut] = None
    limitations: list[str] = []
    errors: list[str] = []
