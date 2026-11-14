"""
Backend integration tests — Member 3.

Runs with standard Python unittest or pytest.
Covers:
- Liveness probe: GET /api/health
- Analysis endpoint: POST /api/analyze
- Provenance and mock_mode labeling
- ID lineage preservation
- Request validation (empty query, oversized query)
- Pipeline bridge integration
"""

import unittest
from pydantic import ValidationError

from backend.app import health_check
from backend.models.requests import AnalyzeRequest
from backend.routes.analyze import analyze
from backend.pipeline import run_pipeline


class TestBackend(unittest.TestCase):
    """Member 3 backend integration test suite."""

    def test_health_check(self):
        """GET /api/health returns healthy status and service version."""
        res = health_check()
        self.assertEqual(res.status, "healthy")
        self.assertEqual(res.service, "verityos-backend")
        self.assertTrue(len(res.version) > 0)

    def test_analyze_success(self):
        """POST /api/analyze returns valid response with all agreed fields."""
        req = AnalyzeRequest(query="Market research for Company X revenue FY2025")
        res = analyze(req)
        self.assertEqual(res.status, "SUCCESS")
        self.assertTrue(res.task_id.startswith("task-"))
        self.assertIn(res.decision, ("APPROVED", "QUARANTINED", "REJECTED", "INSUFFICIENT_DATA"))
        self.assertIsInstance(res.trust_score, float)
        self.assertIsInstance(res.trust_grade, str)
        self.assertTrue(len(res.claims) > 0)
        self.assertTrue(len(res.evidence) > 0)
        self.assertTrue(len(res.verification_results) > 0)
        self.assertIsNotNone(res.trust_evaluation)
        self.assertIsNotNone(res.provenance)

    def test_mock_mode_is_labelled(self):
        """Mock pipeline mode must be visibly labelled in provenance and limitations."""
        req = AnalyzeRequest(query="Test provenance mock labeling")
        res = analyze(req)
        self.assertIsNotNone(res.provenance)
        self.assertTrue(res.provenance.mock_mode)
        self.assertTrue(any("MOCK" in lim for lim in res.limitations))

    def test_id_lineage(self):
        """Verify claim_id and evidence_id lineage is preserved across stages."""
        req = AnalyzeRequest(query="Check ID lineage")
        res = analyze(req)
        claim_ids = {c.claim_id for c in res.claims}
        evidence_ids = {e.evidence_id for e in res.evidence}

        for vr in res.verification_results:
            self.assertIn(vr.claim_id, claim_ids)
        for c in res.claims:
            for eid in c.evidence_ids:
                self.assertIn(eid, evidence_ids)

    def test_options_passthrough(self):
        """Options parameter is passed through to the pipeline."""
        req = AnalyzeRequest(
            query="Analyze with options",
            options={"mode": "collaborative", "max_depth": 2}
        )
        res = analyze(req)
        self.assertEqual(res.status, "SUCCESS")

    def test_validation_empty_query(self):
        """Pydantic rejects an empty query with validation error."""
        with self.assertRaises(ValidationError):
            AnalyzeRequest(query="")

    def test_validation_query_too_long(self):
        """Pydantic rejects queries exceeding 5000 characters."""
        with self.assertRaises(ValidationError):
            AnalyzeRequest(query="x" * 5001)

    def test_pipeline_bridge_direct(self):
        """run_pipeline bridge function handles custom task_id and options."""
        res = run_pipeline("Sample query", "task-custom-001")
        self.assertEqual(res["task_id"], "task-custom-001")
        self.assertEqual(res["status"], "SUCCESS")
        self.assertIn("trust_evaluation", res)


if __name__ == "__main__":
    unittest.main()
