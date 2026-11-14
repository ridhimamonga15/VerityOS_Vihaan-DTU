"""Main Trust Engine Coordinator for VerityOS.

This module is the primary integration coordinator for the VerityOS Trust Engine,
exposing `evaluate_trust_engine(verification_packet)` as specified in the integration
contract with Member 1.

Workflow Orchestration:
1. Input Validation & Parsing:
   Safely extracts `task_id`, `claims`, `evidence`, and `verification_results`
   from Member 1's common envelope (supporting both dicts and Pydantic schemas).
2. Domain Checking:
   - Source Reliability Checker (`source_checker.py`)
   - Freshness Checker (`freshness_checker.py`)
   - Consistency Checker (`consistency_checker.py`)
   - Integrity Checker (`integrity_checker.py`)
3. Multidimensional Evaluation:
   - Source Quality: Average credibility from SourceChecker.
   - Evidence Support: Ratio from VerificationResults (SUPPORTED vs CONTRADICTED vs INSUFFICIENT).
   - Freshness: Evaluated from valid publication dates (omitted dates remain unavailable).
   - Corroboration: Multi-source independent domain diversity per claim.
   - Consistency: Evaluated from structured numerical/date metrics (None if absent).
   - Data Quality: Completeness of evidence metadata & cryptographic integrity.
4. Scoring & Normalization:
   Invokes `scoring.py` to calculate overall trust score and coverage ratio without
   fabricating scores for unavailable dimensions.
5. Governance Policy Execution:
   Invokes `policy_engine.py` to evaluate thresholds and critical safety flags
   (INTEGRITY_MISMATCH, CONTRADICTED_CLAIM, INCONSISTENT_DATA, FUTURE_DATED_EVIDENCE, LOW_COVERAGE).
6. Granular Per-Claim Breakdown:
   Produces an individual evaluation for each claim.
7. Envelope Packaging:
   Returns the final output using Member 1's standardized envelope format.
"""

from typing import Any, Dict, List, Optional, Set, Tuple, Union
from urllib.parse import urlparse

from trust_engine.config import (
    DEFAULT_GRADE_THRESHOLDS,
    DEFAULT_POLICY_THRESHOLDS,
    DEFAULT_WEIGHTS,
    TrustEngineConfig,
)
from trust_engine.consistency_checker import ConsistencyChecker, ConsistencyStatus
from trust_engine.freshness_checker import FreshnessChecker, FreshnessStatus
from trust_engine.integrity_checker import IntegrityChecker, IntegrityStatus
from trust_engine.policy_engine import (
    CriticalFlag,
    PolicyDecision,
    PolicyEngine,
    PolicyStatus,
    TrustGrade,
)
from trust_engine.schemas import (
    Claim,
    Evidence,
    TrustEngineInput,
    VerificationResult,
    VerificationStatus,
)
from trust_engine.scoring import ScoringStatus, TrustScorer, calculate_trust_score
from trust_engine.source_checker import SourceChecker


# ---------------------------------------------------------------------------
# Helper: Domain Extraction for Corroboration
# ---------------------------------------------------------------------------

def _extract_domain(url: Optional[str]) -> Optional[str]:
    """Extract registered domain / netloc from URL string."""
    if not url or not isinstance(url, str):
        return None
    try:
        parsed = urlparse(url.strip())
        domain = parsed.netloc.lower()
        if domain.startswith("www."):
            domain = domain[4:]
        return domain if domain else None
    except Exception:
        return None


# ---------------------------------------------------------------------------
# Coordinator Class
# ---------------------------------------------------------------------------

class TrustEngineCoordinator:
    """Coordinates all Trust Engine components into a unified evaluation pipeline."""

    def __init__(
        self,
        config: Optional[Union[TrustEngineConfig, Dict[str, Any]]] = None,
        weights: Optional[Dict[str, float]] = None,
        policy_thresholds: Optional[Dict[str, float]] = None,
        grade_thresholds: Optional[Dict[str, float]] = None,
    ):
        """Initialize all Trust Engine sub-components with shared configuration."""
        if isinstance(config, TrustEngineConfig):
            self.config = config
        elif isinstance(config, dict):
            self.config = TrustEngineConfig(
                weights=weights or config.get("weights", DEFAULT_WEIGHTS.copy()),
                policy_thresholds=policy_thresholds or config.get("policy_thresholds", DEFAULT_POLICY_THRESHOLDS.copy()),
                grade_thresholds=grade_thresholds or config.get("grade_thresholds", DEFAULT_GRADE_THRESHOLDS.copy()),
            )
        else:
            self.config = TrustEngineConfig(
                weights=weights or DEFAULT_WEIGHTS.copy(),
                policy_thresholds=policy_thresholds or DEFAULT_POLICY_THRESHOLDS.copy(),
                grade_thresholds=grade_thresholds or DEFAULT_GRADE_THRESHOLDS.copy(),
            )

        # Initialize domain checkers
        self.source_checker = SourceChecker()
        self.freshness_checker = FreshnessChecker()
        self.consistency_checker = ConsistencyChecker()
        self.integrity_checker = IntegrityChecker()

        # Initialize scoring and policy engines
        self.scorer = TrustScorer(config=self.config)
        self.policy_engine = PolicyEngine(config=self.config)

    def evaluate(self, verification_packet: Any) -> Dict[str, Any]:
        """Execute trust evaluation across all dimensions for a verification packet.
        
        Args:
            verification_packet: Common envelope dictionary or TrustEngineInput instance.
            
        Returns:
            Standardized response envelope dictionary.
        """
        # 1. Parse and validate input envelope
        task_id, claims, evidence_items, verification_results, error_msg = self._parse_input(verification_packet)

        if error_msg:
            return self._build_error_response(
                task_id=task_id or "task_unknown",
                error_message=error_msg,
            )

        # 2. Index evidence by evidence_id
        evidence_by_id: Dict[str, Dict[str, Any]] = {}
        for ev in evidence_items:
            ev_dict = self._evidence_to_dict(ev)
            eid = ev_dict.get("evidence_id")
            if eid:
                evidence_by_id[eid] = ev_dict

        # 3. Index verification results by claim_id
        verifications_by_claim: Dict[str, Dict[str, Any]] = {}
        for vr in verification_results:
            vr_dict = self._verification_to_dict(vr)
            cid = vr_dict.get("claim_id")
            if cid:
                verifications_by_claim[cid] = vr_dict

        # Track triggered critical flags
        triggered_flags: Set[str] = set()

        # -------------------------------------------------------------------
        # A. Source Checker Evaluation
        # -------------------------------------------------------------------
        source_quality_score: Optional[float] = None
        source_reports_by_id: Dict[str, Dict[str, Any]] = {}

        if evidence_items:
            evidence_dicts = [self._evidence_to_dict(e) for e in evidence_items]
            source_batch = self.source_checker.evaluate_sources(evidence_dicts)
            source_quality_score = source_batch.get("average_reliability_score")
            for rep in source_batch.get("source_reports", []):
                eid = rep.get("evidence_id")
                if eid:
                    source_reports_by_id[eid] = rep

        # -------------------------------------------------------------------
        # B. Freshness Checker Evaluation
        # -------------------------------------------------------------------
        freshness_score: Optional[float] = None
        freshness_reports_by_id: Dict[str, Dict[str, Any]] = {}

        if evidence_items:
            evidence_dicts = [self._evidence_to_dict(e) for e in evidence_items]
            freshness_batch = self.freshness_checker.evaluate_evidences(evidence_dicts)
            freshness_score = freshness_batch.get("average_freshness_score")

            for rep in freshness_batch.get("reports", []):
                eid = rep.get("evidence_id")
                if eid:
                    freshness_reports_by_id[eid] = rep
                # Check for future-dated evidence flag
                if rep.get("freshness_status") == FreshnessStatus.FUTURE_DATED.value:
                    triggered_flags.add(CriticalFlag.FUTURE_DATED_EVIDENCE.value)

        # -------------------------------------------------------------------
        # C. Consistency Checker Evaluation
        # -------------------------------------------------------------------
        consistency_score: Optional[float] = None
        consistency_reports_by_claim: Dict[str, Dict[str, Any]] = {}

        # Collect structured data attached to claims or evidence metadata
        structured_data_map: Dict[str, List[Dict[str, Any]]] = {}
        has_any_structured_data = False

        for clm in claims:
            cid = clm.get("claim_id") if isinstance(clm, dict) else getattr(clm, "claim_id", None)
            if not cid:
                continue

            # Look for structured data in claim metadata or linked evidence metadata
            s_list: List[Dict[str, Any]] = []
            clm_meta = (clm.get("metadata") or {}) if isinstance(clm, dict) else (getattr(clm, "metadata", None) or {})
            if "structured_data" in clm_meta and isinstance(clm_meta["structured_data"], list):
                s_list.extend(clm_meta["structured_data"])

            eids = clm.get("evidence_ids", []) if isinstance(clm, dict) else getattr(clm, "evidence_ids", [])
            for eid in eids:
                ev_obj = evidence_by_id.get(eid)
                if ev_obj:
                    ev_meta = ev_obj.get("metadata") or {}
                    if "structured_data" in ev_meta and isinstance(ev_meta["structured_data"], list):
                        s_list.extend(ev_meta["structured_data"])

            if s_list:
                structured_data_map[cid] = s_list
                has_any_structured_data = True

        if claims and has_any_structured_data:
            consistency_batch = self.consistency_checker.evaluate_claims(
                claims=[self._claim_to_dict(c) for c in claims],
                evidence_items=[self._evidence_to_dict(e) for e in evidence_items],
                structured_data_map=structured_data_map,
            )
            consistency_score = consistency_batch.get("average_consistency_score")
            for rep in consistency_batch.get("reports", []):
                cid = rep.get("claim_id")
                if cid:
                    consistency_reports_by_claim[cid] = rep
                if rep.get("consistency_status") == ConsistencyStatus.INCONSISTENT.value:
                    triggered_flags.add(CriticalFlag.INCONSISTENT_DATA.value)
        else:
            # If no structured data, consistency remains None
            consistency_score = None

        # -------------------------------------------------------------------
        # D. Integrity Checker Evaluation
        # -------------------------------------------------------------------
        integrity_evaluations: List[Dict[str, Any]] = []
        has_actual_integrity_check = False
        integrity_intact_count = 0
        integrity_tested_count = 0

        for ev in evidence_items:
            ev_dict = self._evidence_to_dict(ev)
            meta = ev_dict.get("metadata") or {}
            local_path = meta.get("file_path") or meta.get("local_path")
            base_hash = ev_dict.get("sha256_hash")

            if local_path and base_hash:
                has_actual_integrity_check = True
                rep = self.integrity_checker.check_evidence_integrity(ev_dict, file_path=local_path)
                integrity_evaluations.append(rep)
                integrity_tested_count += 1
                if rep.get("integrity_status") == IntegrityStatus.INTACT.value:
                    integrity_intact_count += 1
                elif rep.get("integrity_status") == IntegrityStatus.MODIFIED.value:
                    triggered_flags.add(CriticalFlag.INTEGRITY_MISMATCH.value)

        # -------------------------------------------------------------------
        # E. Evidence Support Evaluation (from Member 1 Verification Results)
        # -------------------------------------------------------------------
        evidence_support_score: Optional[float] = None
        supported_claims_count = 0
        contradicted_claims_count = 0
        insufficient_claims_count = 0

        if verification_results:
            for vr in verification_results:
                vr_dict = self._verification_to_dict(vr)
                status = str(vr_dict.get("status", "")).strip().upper()
                if status == VerificationStatus.SUPPORTED.value:
                    supported_claims_count += 1
                elif status == VerificationStatus.CONTRADICTED.value:
                    contradicted_claims_count += 1
                    triggered_flags.add(CriticalFlag.CONTRADICTED_CLAIM.value)
                else:
                    insufficient_claims_count += 1

            total_v = len(verification_results)
            if total_v > 0:
                # Deterministic support scoring:
                # SUPPORTED = +1.0, INSUFFICIENT = 0.0, CONTRADICTED = 0.0 (and triggers flag)
                # Formula: supported_claims / total_claims
                evidence_support_score = round(supported_claims_count / total_v, 4)
        elif claims:
            # Claims exist but no verification results were provided
            evidence_support_score = None

        # -------------------------------------------------------------------
        # F. Corroboration Evaluation (Multi-Source Domain Diversity)
        # -------------------------------------------------------------------
        corroboration_score: Optional[float] = None
        if claims and evidence_items:
            claim_corroboration_scores: List[float] = []

            for clm in claims:
                clm_dict = self._claim_to_dict(clm)
                eids = clm_dict.get("evidence_ids", [])
                domains: Set[str] = set()

                for eid in eids:
                    ev_item = evidence_by_id.get(eid)
                    if ev_item:
                        d = _extract_domain(ev_item.get("source_url"))
                        if d:
                            domains.add(d)

                if len(domains) >= 2:
                    # Multi-source corroboration
                    score_c = min(1.0, 0.60 + (len(domains) * 0.15))
                    claim_corroboration_scores.append(round(score_c, 4))
                elif len(domains) == 1:
                    # Single source backing
                    claim_corroboration_scores.append(0.50)
                else:
                    # No verifiable domains
                    pass

            if claim_corroboration_scores:
                corroboration_score = round(
                    sum(claim_corroboration_scores) / len(claim_corroboration_scores), 4
                )
            else:
                corroboration_score = None

        # -------------------------------------------------------------------
        # G. Data Quality Evaluation
        # -------------------------------------------------------------------
        data_quality_score: Optional[float] = None
        if evidence_items:
            completeness_scores: List[float] = []
            for ev in evidence_items:
                ev_dict = self._evidence_to_dict(ev)
                fields = [
                    bool(ev_dict.get("evidence_id")),
                    bool(ev_dict.get("source_url")),
                    bool(ev_dict.get("source_title")),
                    bool(ev_dict.get("snippet")),
                ]
                comp = sum(fields) / len(fields)
                completeness_scores.append(comp)

            avg_completeness = sum(completeness_scores) / len(completeness_scores)

            if has_actual_integrity_check and integrity_tested_count > 0:
                integrity_ratio = integrity_intact_count / integrity_tested_count
                data_quality_score = round((0.60 * avg_completeness) + (0.40 * integrity_ratio), 4)
            else:
                data_quality_score = round(avg_completeness, 4)
        elif not claims and not evidence_items:
            data_quality_score = None

        # -------------------------------------------------------------------
        # H. Scoring Engine Aggregation
        # -------------------------------------------------------------------
        dimension_scores = {
            "source_quality": source_quality_score,
            "evidence_support": evidence_support_score,
            "freshness": freshness_score,
            "corroboration": corroboration_score,
            "consistency": consistency_score,
            "data_quality": data_quality_score,
        }

        scoring_result = self.scorer.score(dimension_scores)

        # -------------------------------------------------------------------
        # I. Policy Engine Evaluation
        # -------------------------------------------------------------------
        policy_report = self.policy_engine.evaluate(
            scoring_result=scoring_result,
            flags=list(triggered_flags),
        )

        # -------------------------------------------------------------------
        # J. Per-Claim Evaluations
        # -------------------------------------------------------------------
        claim_evaluations: List[Dict[str, Any]] = []
        for clm in claims:
            clm_dict = self._claim_to_dict(clm)
            cid = clm_dict.get("claim_id", "unknown_claim")
            vr_info = verifications_by_claim.get(cid, {})

            # Per-claim evidence support
            v_status = vr_info.get("status", "UNVERIFIED")
            if v_status == VerificationStatus.SUPPORTED.value:
                clm_support_score = 1.0
            elif v_status == VerificationStatus.CONTRADICTED.value:
                clm_support_score = 0.0
            elif v_status == VerificationStatus.INSUFFICIENT.value:
                clm_support_score = 0.0
            else:
                clm_support_score = None

            # Gather linked evidence sources and freshness
            eids = clm_dict.get("evidence_ids", [])
            sq_list = [source_reports_by_id[eid]["reliability_score"] for eid in eids if eid in source_reports_by_id]
            fr_list = [freshness_reports_by_id[eid]["freshness_score"] for eid in eids if eid in freshness_reports_by_id and freshness_reports_by_id[eid]["freshness_score"] is not None]

            clm_sq = round(sum(sq_list) / len(sq_list), 4) if sq_list else None
            clm_fr = round(sum(fr_list) / len(fr_list), 4) if fr_list else None

            # Consistency for this claim
            clm_cons_rep = consistency_reports_by_claim.get(cid)
            clm_cons = clm_cons_rep.get("consistency_score") if clm_cons_rep else None

            # Local flags for this claim
            clm_flags: List[str] = []
            if v_status == VerificationStatus.CONTRADICTED.value:
                clm_flags.append(CriticalFlag.CONTRADICTED_CLAIM.value)
            if clm_cons_rep and clm_cons_rep.get("consistency_status") == ConsistencyStatus.INCONSISTENT.value:
                clm_flags.append(CriticalFlag.INCONSISTENT_DATA.value)

            claim_evaluations.append({
                "claim_id": cid,
                "claim_text": clm_dict.get("claim_text", ""),
                "verification_status": v_status,
                "supporting_evidence_ids": vr_info.get("supporting_evidence_ids", []),
                "contradicting_evidence_ids": vr_info.get("contradicting_evidence_ids", []),
                "evidence_support_score": clm_support_score,
                "source_quality_score": clm_sq,
                "freshness_score": clm_fr,
                "consistency_score": clm_cons,
                "triggered_flags": clm_flags,
                "explanation": vr_info.get("explanation") or f"Claim '{cid}' evaluated with status {v_status}.",
            })

        # -------------------------------------------------------------------
        # K. Trust Report Generation
        # -------------------------------------------------------------------
        recommendations: List[str] = []
        if policy_report["policy_decision"] == PolicyDecision.PASS.value:
            recommendations.append("Overall trust score meets PASS criteria; safe to proceed.")
        elif policy_report["policy_decision"] == PolicyDecision.REVIEW.value:
            recommendations.append("Secondary human or supervisor review required before execution.")
            if CriticalFlag.INTEGRITY_MISMATCH.value in policy_report["triggered_flags"]:
                recommendations.append("Investigate local file hash discrepancies against baseline.")
            if CriticalFlag.CONTRADICTED_CLAIM.value in policy_report["triggered_flags"]:
                recommendations.append("Review claims contradicted by evidence.")
            if CriticalFlag.INCONSISTENT_DATA.value in policy_report["triggered_flags"]:
                recommendations.append("Reconcile conflicting numerical values or units across sources.")
        else:
            recommendations.append("Execution blocked: trust score is below the minimum threshold.")

        trust_report = {
            "summary": (
                f"Evaluation completed with decision {policy_report['policy_decision']} "
                f"(Score: {policy_report['overall_trust_score'] if policy_report['overall_trust_score'] is not None else 'N/A'}, "
                f"Grade: {policy_report['trust_grade']})."
            ),
            "explanation": policy_report["explanation"],
            "warnings": policy_report["warnings"],
            "recommendations": recommendations,
        }

        # -------------------------------------------------------------------
        # L. Final Standard Envelope Response
        # -------------------------------------------------------------------
        return {
            "task_id": task_id,
            "status": "success",
            "agent": "trust_engine",
            "data": {
                "overall_trust_score": policy_report["overall_trust_score"],
                "trust_grade": policy_report["trust_grade"],
                "policy_decision": policy_report["policy_decision"],
                "coverage_ratio": policy_report["coverage_ratio"],
                "dimension_scores": scoring_result["dimension_scores"],
                "dimension_breakdown": scoring_result["dimension_breakdown"],
                "available_dimensions": scoring_result["available_dimensions"],
                "unavailable_dimensions": scoring_result["unavailable_dimensions"],
                "triggered_flags": policy_report["triggered_flags"],
                "claim_evaluations": claim_evaluations,
                "trust_report": trust_report,
            },
            "error": None,
        }

    # -----------------------------------------------------------------------
    # Internal Input Parsing & Conversion
    # -----------------------------------------------------------------------

    def _parse_input(
        self,
        packet: Any
    ) -> Tuple[Optional[str], List[Any], List[Any], List[Any], Optional[str]]:
        """Safely parse claims, evidence, and verification results from packet.
        
        Returns:
            Tuple of (task_id, claims, evidence, verification_results, error_msg).
        """
        if packet is None:
            return None, [], [], [], "Verification packet is None."

        # Case 1: Pydantic TrustEngineInput
        if isinstance(packet, TrustEngineInput):
            data = packet.data
            return (
                packet.task_id,
                getattr(data, "claims", []),
                getattr(data, "evidence", []),
                getattr(data, "verification_results", []),
                None,
            )

        # Case 2: Dictionary
        if isinstance(packet, dict):
            if not packet:
                return "task_unknown", [], [], [], "Empty verification packet dictionary."

            task_id = packet.get("task_id")
            if not task_id or not str(task_id).strip():
                return None, [], [], [], "Missing or invalid 'task_id' in envelope."

            data = packet.get("data")
            if data is None:
                # If packet has claims directly at top level for backwards tolerance
                if "claims" in packet:
                    claims = packet.get("claims", [])
                    evidence = packet.get("evidence", [])
                    verifications = packet.get("verification_results", [])
                    return str(task_id).strip(), claims, evidence, verifications, None
                return str(task_id).strip(), [], [], [], "Missing 'data' payload in envelope."

            if isinstance(data, dict):
                claims = data.get("claims", [])
                evidence = data.get("evidence", [])
                verifications = data.get("verification_results", [])
                return str(task_id).strip(), claims, evidence, verifications, None
            else:
                claims = getattr(data, "claims", [])
                evidence = getattr(data, "evidence", [])
                verifications = getattr(data, "verification_results", [])
                return str(task_id).strip(), claims, evidence, verifications, None

        return None, [], [], [], f"Unsupported packet type: {type(packet).__name__}."

    def _evidence_to_dict(self, ev: Any) -> Dict[str, Any]:
        """Convert Evidence model or dict to dictionary safely."""
        if isinstance(ev, dict):
            return ev
        if hasattr(ev, "model_dump"):
            return ev.model_dump()
        if hasattr(ev, "dict"):
            return ev.dict()
        return {
            "evidence_id": getattr(ev, "evidence_id", None),
            "source_url": getattr(ev, "source_url", None),
            "source_title": getattr(ev, "source_title", None),
            "snippet": getattr(ev, "snippet", None),
            "source_type": getattr(ev, "source_type", None),
            "publication_date": getattr(ev, "publication_date", None),
            "sha256_hash": getattr(ev, "sha256_hash", None),
            "metadata": getattr(ev, "metadata", {}) or {},
        }

    def _claim_to_dict(self, clm: Any) -> Dict[str, Any]:
        """Convert Claim model or dict to dictionary safely."""
        if isinstance(clm, dict):
            return clm
        if hasattr(clm, "model_dump"):
            return clm.model_dump()
        if hasattr(clm, "dict"):
            return clm.dict()
        return {
            "claim_id": getattr(clm, "claim_id", None),
            "claim_text": getattr(clm, "claim_text", ""),
            "evidence_ids": getattr(clm, "evidence_ids", []) or [],
            "metadata": getattr(clm, "metadata", {}) or {},
        }

    def _verification_to_dict(self, vr: Any) -> Dict[str, Any]:
        """Convert VerificationResult model or dict to dictionary safely."""
        if isinstance(vr, dict):
            return vr
        if hasattr(vr, "model_dump"):
            return vr.model_dump()
        if hasattr(vr, "dict"):
            return vr.dict()
        return {
            "claim_id": getattr(vr, "claim_id", None),
            "status": getattr(vr, "status", None),
            "supporting_evidence_ids": getattr(vr, "supporting_evidence_ids", []) or [],
            "contradicting_evidence_ids": getattr(vr, "contradicting_evidence_ids", []) or [],
            "explanation": getattr(vr, "explanation", None),
        }

    def _build_error_response(self, task_id: str, error_message: str) -> Dict[str, Any]:
        """Build standardized error response for malformed envelopes."""
        return {
            "task_id": task_id,
            "status": "error",
            "agent": "trust_engine",
            "data": {
                "overall_trust_score": None,
                "trust_grade": TrustGrade.UNAVAILABLE.value,
                "policy_decision": PolicyDecision.REVIEW.value,
                "coverage_ratio": 0.0,
                "dimension_scores": {dim: None for dim in DEFAULT_WEIGHTS.keys()},
                "dimension_breakdown": {},
                "available_dimensions": [],
                "unavailable_dimensions": list(DEFAULT_WEIGHTS.keys()),
                "triggered_flags": [],
                "claim_evaluations": [],
                "trust_report": {
                    "summary": f"Evaluation error: {error_message}",
                    "explanation": error_message,
                    "warnings": [error_message],
                    "recommendations": ["Verify and resubmit input packet adhering to the integration schema."],
                },
            },
            "error": error_message,
        }


# ---------------------------------------------------------------------------
# Global Public Integration Function
# ---------------------------------------------------------------------------

def evaluate_trust_engine(verification_packet: Any) -> Dict[str, Any]:
    """Primary integration function exposed to Member 1 and the VerityOS system.
    
    Accepts Member 1's common envelope, executes all Trust Engine checkers,
    evaluates multidimensional scoring, executes governance policy, and
    returns the complete standardized envelope response.
    
    Args:
        verification_packet: Dictionary or TrustEngineInput instance.
        
    Returns:
        Standardized output response dictionary.
    """
    coordinator = TrustEngineCoordinator()
    return coordinator.evaluate(verification_packet)

