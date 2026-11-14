"""
VerityOS Shared Schemas & Common Data Contracts
================================================

PROVISIONAL TEAM CONTRACT BASELINE:
This module defines the canonical data structures, envelopes, and enums shared across:
- Member 1: AI Agents and Orchestration
- Member 2: Trust Engine
- Member 3: Backend & API
- Member 4: Frontend Dashboard

STATUS:
PROVISIONAL — Subject to formal cross-member approval as annotated on each schema:
- VerificationPacket / VerificationPacketData -> APPROVAL PENDING: Member 2
- TrustAssessmentRecord / TrustEngineOutput   -> APPROVAL PENDING: Member 2
- FinalPipelineResponse / ProductState         -> APPROVAL PENDING: Member 3 & Member 4
- ModuleEnvelope, EvidenceRecord, ClaimRecord -> PROVISIONAL BASELINE
"""

from enum import Enum
from typing import Any, Optional
from pydantic import BaseModel, ConfigDict, Field, model_validator


# ============================================================================
# Shared Enums
# ============================================================================

class ExecutionMode(str, Enum):
    """
    Execution mode indicator to strictly separate simulated/test runs from live runs.
    APPROVAL STATUS: Provisional baseline agreed for hackathon MVP.
    """
    MOCK = "mock"
    LIVE = "live"


class ModuleStatus(str, Enum):
    """
    Status of an individual agent execution or module envelope.
    APPROVAL STATUS: Provisional baseline (Agreed in Project Blueprint p. 6).
    """
    SUCCESS = "SUCCESS"
    EMPTY = "EMPTY"
    ERROR = "ERROR"


class VerificationStatus(str, Enum):
    """
    Verification outcome for an individual atomic claim.
    APPROVAL STATUS: Proposed baseline (Agreed in Project Blueprint p. 6).
    """
    SUPPORTED = "SUPPORTED"
    CONTRADICTED = "CONTRADICTED"
    INSUFFICIENT = "INSUFFICIENT"


class TrustDecision(str, Enum):
    """
    Evaluation decision emitted by Member 2's Trust & Verification Engine.
    APPROVAL STATUS: Member 2 contract (Agreed in Project Blueprint p. 7).
    """
    PASS = "PASS"
    REVIEW = "REVIEW"
    REJECT = "REJECT"


class ProductState(str, Enum):
    """
    User-facing product state derived by Orchestrator policy gate.
    APPROVAL STATUS: APPROVAL PENDING from Member 3 (Backend) & Member 4 (Frontend).
    """
    APPROVED = "APPROVED"
    QUARANTINED = "QUARANTINED"
    REJECTED = "REJECTED"
    INSUFFICIENT_DATA = "INSUFFICIENT_DATA"
    ERROR = "ERROR"


# ============================================================================
# Standard Module Envelope
# ============================================================================

class ModuleEnvelope(BaseModel):
    """
    Universal envelope wrapping internal agent inputs and outputs.
    APPROVAL STATUS: Provisional baseline agreed across all modules.
    """
    model_config = ConfigDict(extra="forbid")

    task_id: str = Field(description="Unique task identifier preserved through pipeline")
    status: ModuleStatus = Field(description="Execution status: SUCCESS, EMPTY, or ERROR")
    agent: str = Field(description="Stable module identifier, e.g., 'research_agent'")
    mode: ExecutionMode = Field(default=ExecutionMode.MOCK, description="Execution mode: mock or live")
    data: dict[str, Any] = Field(default_factory=dict, description="Stage-specific payload")
    error: Optional[str] = Field(default=None, description="Safe user-facing error message (no raw tracebacks)")


# ============================================================================
# Research & Evidence Data Entities
# ============================================================================

class EvidenceRecord(BaseModel):
    """
    Individual collected evidence record.
    APPROVAL STATUS: Provisional baseline (Agreed in Project Blueprint p. 6).
    """
    model_config = ConfigDict(extra="forbid")

    evidence_id: str = Field(description="Stable evidence identifier (e.g., 'E1', 'E2')")
    source_url: str = Field(description="Source URL, document identifier, or file reference")
    source_title: str = Field(description="Human-readable title of the source")
    snippet: str = Field(description="Verbatim or extracted text snippet supporting/refuting claims")
    source_type: str = Field(default="website", description="Source category: website, filing, document, dataset")
    published_at: Optional[str] = Field(default=None, description="ISO date (YYYY-MM-DD) or None if unknown")
    retrieved_at: str = Field(description="ISO timestamp when evidence was collected")
    content_hash: Optional[str] = Field(default=None, description="SHA-256 hex digest of the snippet or file")
    mode: ExecutionMode = Field(default=ExecutionMode.MOCK, description="Execution mode: mock or live")
    is_mock: bool = Field(default=True, description="Strict transparency flag: True if synthetic/mock data")

    @model_validator(mode="after")
    def sync_mode_and_mock(self) -> "EvidenceRecord":
        """Ensure LIVE mode is never erroneously flagged as mock, and sync mode with is_mock."""
        if self.mode == ExecutionMode.LIVE:
            self.is_mock = False
        elif not self.is_mock:
            self.mode = ExecutionMode.LIVE
        return self


# ============================================================================
# Claim & Verification Data Entities
# ============================================================================

class ClaimRecord(BaseModel):
    """
    Atomic factual claim extracted from collected evidence.
    Rule: Every claim MUST link to at least one evidence_id (unsupported claims forbidden).
    APPROVAL STATUS: Provisional baseline (Agreed in Project Blueprint p. 6).
    """
    model_config = ConfigDict(extra="forbid")

    claim_id: str = Field(description="Stable claim identifier (e.g., 'C1', 'C2')")
    claim_text: str = Field(description="Exact atomic statement being assessed")
    evidence_ids: list[str] = Field(
        min_length=1,
        description="List of evidence IDs that link to and substantiate this claim"
    )
    subject: Optional[str] = Field(default=None, description="Subject entity (e.g., 'Company X')")
    predicate: Optional[str] = Field(default=None, description="Predicate or attribute (e.g., 'revenue')")
    value: Optional[str] = Field(default=None, description="Value or metric (e.g., 'INR 50 crore')")
    time_period: Optional[str] = Field(default=None, description="Relevant time period (e.g., 'FY2025')")


class VerificationResultRecord(BaseModel):
    """
    Verification assessment for a single claim against available evidence.
    APPROVAL STATUS: Provisional baseline (Agreed in Project Blueprint p. 6).
    """
    model_config = ConfigDict(extra="forbid")

    claim_id: str = Field(description="ID of the claim being verified")
    status: VerificationStatus = Field(description="SUPPORTED, CONTRADICTED, or INSUFFICIENT")
    supporting_evidence_ids: list[str] = Field(
        default_factory=list,
        description="Evidence IDs corroborating the claim"
    )
    contradicting_evidence_ids: list[str] = Field(
        default_factory=list,
        description="Evidence IDs conflicting with or refuting the claim"
    )
    explanation: str = Field(description="Clear explanation of the verification finding")
    confidence_estimate: float = Field(
        default=1.0,
        ge=0.0,
        le=1.0,
        description="Calibrated confidence estimate (0.0 to 1.0)"
    )


# ============================================================================
# Member 2 Hand-off: Verification Packet (Trust Engine Input)
# ============================================================================

class VerificationPacketData(BaseModel):
    """
    Data payload packaged for Member 2's Trust Engine.
    APPROVAL STATUS: APPROVAL PENDING from Member 2 (Trust Engine).
    """
    model_config = ConfigDict(extra="forbid")

    claims: list[ClaimRecord] = Field(default_factory=list, description="All extracted atomic claims")
    evidence: list[EvidenceRecord] = Field(default_factory=list, description="All collected evidence records")
    verification_results: list[VerificationResultRecord] = Field(
        default_factory=list,
        description="All claim verification results"
    )


class VerificationPacket(BaseModel):
    """
    Complete verification envelope passed to evaluate_trust_engine().
    APPROVAL STATUS: APPROVAL PENDING from Member 2 (Trust Engine).
    """
    model_config = ConfigDict(extra="forbid")

    task_id: str = Field(description="Immutable task identifier")
    status: ModuleStatus = Field(default=ModuleStatus.SUCCESS, description="Envelope status")
    agent: str = Field(default="verification_agent", description="Originating agent identifier")
    mode: ExecutionMode = Field(default=ExecutionMode.MOCK, description="Execution mode: mock or live")
    data: VerificationPacketData = Field(description="Structured verification payload")
    error: Optional[str] = Field(default=None, description="Safe error message if stage failed")


# ============================================================================
# Member 2 Output: Trust Engine Assessment
# ============================================================================

class TrustDimensionScores(BaseModel):
    """
    Six-dimension trust evaluation breakdown (0.0 to 100.0).
    APPROVAL STATUS: APPROVAL PENDING from Member 2 (Trust Engine).
    """
    model_config = ConfigDict(extra="forbid")

    source_quality: float = Field(ge=0.0, le=100.0, description="Authority and relevance of sources")
    evidence_support: float = Field(ge=0.0, le=100.0, description="Directness and coverage of evidence")
    freshness: float = Field(ge=0.0, le=100.0, description="Recency and time sensitivity of evidence")
    corroboration: float = Field(ge=0.0, le=100.0, description="Agreement across independent sources")
    consistency: float = Field(ge=0.0, le=100.0, description="Absence of contradictions in facts/dates/units")
    data_quality: float = Field(ge=0.0, le=100.0, description="Completeness, integrity, and schema compliance")


class TrustAssessmentRecord(BaseModel):
    """
    Overall trust assessment record produced by Member 2's Trust Engine.
    APPROVAL STATUS: APPROVAL PENDING from Member 2 (Trust Engine).
    """
    model_config = ConfigDict(extra="forbid")

    overall_score: float = Field(ge=0.0, le=100.0, description="Weighted composite trust score")
    decision: TrustDecision = Field(description="Policy decision: PASS, REVIEW, or REJECT")
    dimension_scores: TrustDimensionScores = Field(description="Scores across the 6 trust dimensions")
    reasons: list[str] = Field(default_factory=list, description="Explanations justifying the decision")
    warnings: list[str] = Field(default_factory=list, description="Any detected flags or warning indicators")
    evaluated_at: str = Field(description="ISO timestamp of trust assessment")


class TrustEngineOutput(BaseModel):
    """
    Standard envelope returned by evaluate_trust_engine().
    APPROVAL STATUS: APPROVAL PENDING from Member 2 (Trust Engine).
    """
    model_config = ConfigDict(extra="forbid")

    task_id: str = Field(description="Immutable task identifier")
    status: ModuleStatus = Field(default=ModuleStatus.SUCCESS, description="Execution status")
    trust_assessment: Optional[TrustAssessmentRecord] = Field(
        default=None,
        description="Assessment details, or None on failure"
    )
    error: Optional[str] = Field(default=None, description="Safe error message if trust evaluation failed")


# ============================================================================
# Audit Trail & Final Orchestrator Response (Member 3 & 4 Contract)
# ============================================================================

class AuditStep(BaseModel):
    """
    Audit log entry recording an individual stage transition.
    APPROVAL STATUS: Provisional baseline for auditability.
    """
    model_config = ConfigDict(extra="forbid")

    stage: str = Field(description="Stage name (e.g., 'research', 'data_extraction', 'verification', 'trust_engine')")
    agent: str = Field(description="Executing agent or module")
    status: ModuleStatus = Field(description="Outcome status of the stage")
    timestamp: str = Field(description="ISO timestamp of event")
    summary: str = Field(description="Human-readable summary of actions taken")
    details: Optional[dict[str, Any]] = Field(default=None, description="Optional diagnostic details")


class FinalPipelineResponse(BaseModel):
    """
    Complete end-to-end response delivered to Member 3 (Backend API)
    and rendered by Member 4 (Frontend Dashboard).
    APPROVAL STATUS: APPROVAL PENDING from Member 3 (Backend) & Member 4 (Frontend).
    """
    model_config = ConfigDict(extra="forbid")

    task_id: str = Field(description="Unique task identifier preserved through pipeline")
    query: str = Field(description="Original user query")
    mode: ExecutionMode = Field(default=ExecutionMode.MOCK, description="Execution mode: mock or live")
    product_state: ProductState = Field(description="Overall product state: APPROVED, QUARANTINED, REJECTED, INSUFFICIENT_DATA, ERROR")
    trust_decision: Optional[TrustDecision] = Field(default=None, description="Trust Engine policy decision")
    overall_trust_score: Optional[float] = Field(default=None, ge=0.0, le=100.0, description="Overall trust score (0-100)")
    summary: str = Field(description="Final plain text summary and conclusion")
    claims: list[ClaimRecord] = Field(default_factory=list, description="Extracted atomic claims")
    evidence: list[EvidenceRecord] = Field(default_factory=list, description="Collected evidence records")
    verification_results: list[VerificationResultRecord] = Field(default_factory=list, description="Claim verification findings")
    trust_assessment: Optional[TrustAssessmentRecord] = Field(default=None, description="Full trust assessment details")
    audit_trail: list[AuditStep] = Field(default_factory=list, description="Complete stage-by-stage audit trail")
    warnings: list[str] = Field(default_factory=list, description="Aggregated warnings and caution notes")
    is_mock: bool = Field(default=True, description="Explicit transparency flag: True if synthetic/mock data")
    error: Optional[str] = Field(default=None, description="Sanitized, user-safe error message (no raw tracebacks)")

    @model_validator(mode="after")
    def sync_mode_and_mock(self) -> "FinalPipelineResponse":
        """Ensure LIVE mode is never erroneously flagged as mock, and sync mode with is_mock."""
        if self.mode == ExecutionMode.LIVE:
            self.is_mock = False
        elif not self.is_mock:
            self.mode = ExecutionMode.LIVE
        return self
