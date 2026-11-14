"""Test Suite for VerityOS Trust Engine.

Includes validation tests for:
- config.py (weights summation, dimension validation, threshold checks)
- schemas.py (envelope parsing, status normalization, optional metadata safety, validation errors)
- integrity_checker.py (SHA-256 hashing, INTACT/MODIFIED/MISSING/ERROR statuses, chunking, security)
- source_checker.py (metadata validation, classification, scoring, reporting, multi-source evaluation)
- freshness_checker.py (date extraction, age calculation, freshness decay, missing/future date handling, batching)
- consistency_checker.py (numeric comparison, unit normalization, dates, reporting periods, batch claims)
"""

from datetime import date, datetime, timedelta, timezone
import hashlib
import os
from pathlib import Path
import tempfile
import unittest

from trust_engine.config import (
    DEFAULT_WEIGHTS,
    DEFAULT_POLICY_THRESHOLDS,
    DEFAULT_GRADE_THRESHOLDS,
    REQUIRED_DIMENSIONS,
    validate_weights,
    validate_policy_thresholds,
    TrustEngineConfig,
)
from trust_engine.schemas import (
    Claim,
    Evidence,
    VerificationResult,
    VerificationStatus,
    TrustEngineInput,
    TrustEngineDataPayload,
)
from trust_engine.integrity_checker import (
    IntegrityChecker,
    IntegrityStatus,
    calculate_file_hash,
    compare_hashes,
    verify_file_integrity,
    generate_integrity_report,
    is_valid_sha256,
)
from trust_engine.source_checker import (
    SourceChecker,
    SourceCategory,
    ReliabilityLevel,
    validate_source_metadata,
    classify_source_type,
    calculate_source_reliability,
    generate_source_report,
    is_valid_url_format,
)
from trust_engine.freshness_checker import (
    FreshnessChecker,
    FreshnessStatus,
    extract_publication_date,
    calculate_evidence_age,
    calculate_freshness_score,
    evaluate_freshness,
    generate_freshness_report,
)
from trust_engine.consistency_checker import (
    ConsistencyChecker,
    ConsistencyStatus,
    ValueComparisonStatus,
    DateComparisonStatus,
    PeriodComparisonStatus,
    normalize_numeric_value,
    compare_numeric_values,
    compare_dates,
    compare_reporting_periods,
    evaluate_consistency,
    generate_consistency_report,
)
from trust_engine.scoring import (
    ScoringStatus,
    TrustScorer,
    calculate_trust_coverage,
    calculate_trust_score,
    calculate_weighted_score,
    validate_dimension_scores,
)
from trust_engine.policy_engine import (
    PolicyEngine,
    PolicyDecision,
    TrustGrade,
    CriticalFlag,
    PolicyStatus,
    calculate_trust_grade,
    determine_policy_decision,
    evaluate_policy,
    generate_policy_report,
)
from trust_engine.trust_engine import (
    TrustEngineCoordinator,
    evaluate_trust_engine,
)


class TestTrustEngineConfig(unittest.TestCase):
    """Tests for config.py settings and validation."""

    def test_default_weights_sum_to_one(self):
        """Verify that default weights sum exactly to 1.0."""
        self.assertTrue(validate_weights(DEFAULT_WEIGHTS))
        self.assertAlmostEqual(sum(DEFAULT_WEIGHTS.values()), 1.0, places=5)

    def test_all_six_required_dimensions_present(self):
        """Verify all six required dimensions exist in default weights."""
        expected = {
            "source_quality", "evidence_support", "freshness",
            "corroboration", "consistency", "data_quality"
        }
        self.assertEqual(REQUIRED_DIMENSIONS, expected)
        self.assertEqual(set(DEFAULT_WEIGHTS.keys()), expected)

    def test_weights_sum_mismatch_raises_value_error(self):
        """Verify that weights not summing to 1.0 trigger a ValueError."""
        invalid_weights = DEFAULT_WEIGHTS.copy()
        invalid_weights["freshness"] = 0.50  # Changes sum to 1.35
        with self.assertRaises(ValueError) as context:
            validate_weights(invalid_weights)
        self.assertIn("must sum to 1.0", str(context.exception))

    def test_missing_dimension_raises_value_error(self):
        """Verify that missing a required dimension triggers a ValueError."""
        incomplete_weights = {"source_quality": 0.5, "freshness": 0.5}
        with self.assertRaises(ValueError) as context:
            validate_weights(incomplete_weights)
        self.assertIn("missing required dimensions", str(context.exception))

    def test_negative_weight_raises_value_error(self):
        """Verify that negative weight values trigger a ValueError."""
        negative_weights = DEFAULT_WEIGHTS.copy()
        negative_weights["consistency"] = -0.10
        negative_weights["data_quality"] = 0.30
        with self.assertRaises(ValueError) as context:
            validate_weights(negative_weights)
        self.assertIn("cannot be negative", str(context.exception))

    def test_policy_thresholds_validation(self):
        """Verify policy threshold validation rules."""
        self.assertTrue(validate_policy_thresholds(DEFAULT_POLICY_THRESHOLDS))
        with self.assertRaises(ValueError):
            validate_policy_thresholds({"pass_min_score": 0.30, "review_min_score": 0.60})

    def test_trust_engine_config_object(self):
        """Verify TrustEngineConfig dataclass instantiation."""
        cfg = TrustEngineConfig()
        self.assertEqual(cfg.max_freshness_days, 365)
        self.assertAlmostEqual(sum(cfg.weights.values()), 1.0, places=5)


class TestTrustEngineSchemas(unittest.TestCase):
    """Tests for schemas.py data models and validation contract."""

    def test_valid_member1_envelope(self):
        """Verify complete common envelope format agreed upon with Member 1."""
        sample_envelope = {
            "task_id": "task_001",
            "status": "success",
            "agent": "orchestrator",
            "data": {
                "claims": [
                    {
                        "claim_id": "C1",
                        "claim_text": "Example claim text",
                        "evidence_ids": ["E1"]
                    }
                ],
                "evidence": [
                    {
                        "evidence_id": "E1",
                        "source_url": "https://example.com",
                        "source_title": "Example Source",
                        "snippet": "Example evidence text",
                        "source_type": "website"
                    }
                ],
                "verification_results": [
                    {
                        "claim_id": "C1",
                        "status": "SUPPORTED",
                        "supporting_evidence_ids": ["E1"],
                        "contradicting_evidence_ids": [],
                        "explanation": "Example explanation"
                    }
                ]
            },
            "error": None
        }
        envelope = TrustEngineInput.from_dict(sample_envelope)
        self.assertEqual(envelope.task_id, "task_001")
        self.assertEqual(envelope.agent, "orchestrator")
        self.assertEqual(len(envelope.data.claims), 1)
        self.assertEqual(envelope.data.claims[0].claim_id, "C1")
        self.assertEqual(len(envelope.data.evidence), 1)
        self.assertEqual(envelope.data.evidence[0].evidence_id, "E1")
        self.assertEqual(len(envelope.data.verification_results), 1)
        self.assertEqual(envelope.data.verification_results[0].status, "SUPPORTED")

    def test_verification_status_normalization(self):
        """Verify that lowercase status strings normalize to uppercase."""
        vr1 = VerificationResult(claim_id="C1", status="supported")
        self.assertEqual(vr1.status, "SUPPORTED")
        vr2 = VerificationResult(claim_id="C2", status="contradicted")
        self.assertEqual(vr2.status, "CONTRADICTED")
        vr3 = VerificationResult(claim_id="C3", status="insufficient")
        self.assertEqual(vr3.status, "INSUFFICIENT")

    def test_invalid_verification_status_raises_value_error(self):
        """Verify that invalid statuses raise a clear ValueError."""
        with self.assertRaises(ValueError) as context:
            VerificationResult(claim_id="C1", status="INVALID_STATUS")
        self.assertIn("Allowed values are", str(context.exception))

    def test_missing_optional_evidence_metadata_handled_safely(self):
        """Verify evidence object handles missing optional fields without errors."""
        ev = Evidence(evidence_id="E99")
        self.assertEqual(ev.evidence_id, "E99")
        self.assertIsNone(ev.source_url)
        self.assertIsNone(ev.source_title)
        self.assertIsNone(ev.snippet)
        self.assertIsNone(ev.publication_date)
        self.assertIsNone(ev.sha256_hash)

    def test_empty_identifiers_raise_value_error(self):
        """Verify empty strings or whitespace identifiers raise meaningful errors."""
        with self.assertRaises(ValueError):
            Claim(claim_id="   ", claim_text="Valid text")
        with self.assertRaises(ValueError):
            Claim(claim_id="C1", claim_text="   ")
        with self.assertRaises(ValueError):
            Evidence(evidence_id="   ")
        with self.assertRaises(ValueError):
            TrustEngineInput(task_id="   ", data=TrustEngineDataPayload())


class TestIntegrityChecker(unittest.TestCase):
    """Tests for integrity_checker.py functions, security, and edge cases."""

    def setUp(self):
        """Create a temporary directory for isolated test files."""
        self.test_dir = tempfile.TemporaryDirectory()
        self.dir_path = Path(self.test_dir.name)

    def tearDown(self):
        """Clean up the temporary directory after tests."""
        self.test_dir.cleanup()

    def _create_temp_file(self, filename: str, content: bytes) -> Path:
        """Helper to create a temporary test file."""
        file_path = self.dir_path / filename
        with open(file_path, "wb") as f:
            f.write(content)
        return file_path

    # 1. Hash generation for a valid file
    def test_hash_generation_valid_file(self):
        """Calculate hash of a known text payload and verify against hashlib."""
        content = b"VerityOS Trust Engine Integrity Test Content"
        file_path = self._create_temp_file("valid.txt", content)
        expected_hash = hashlib.sha256(content).hexdigest().lower()

        calculated_hash = calculate_file_hash(file_path)
        self.assertEqual(calculated_hash, expected_hash)

    # 2. Same file compared against its original hash (INTACT)
    def test_same_file_compared_against_original_hash(self):
        """Verify that an unchanged file matches baseline and returns INTACT."""
        content = b"Financial quarterly report data: Q1 2026."
        file_path = self._create_temp_file("report.txt", content)
        baseline_hash = hashlib.sha256(content).hexdigest()

        # Direct boolean check
        self.assertTrue(verify_file_integrity(file_path, baseline_hash))

        # Structured diagnostic report check
        report = generate_integrity_report(file_path, baseline_hash)
        self.assertEqual(report["integrity_status"], IntegrityStatus.INTACT.value)
        self.assertFalse(report["is_modified"])
        self.assertEqual(report["actual_hash"], baseline_hash.lower())
        self.assertEqual(report["expected_hash"], baseline_hash)

    # 3. Modified file compared against its original hash (MODIFIED)
    def test_modified_file_compared_against_original_hash(self):
        """Verify that modified file contents trigger MODIFIED status."""
        original_content = b"Sensor reading = 42.0"
        file_path = self._create_temp_file("sensor.log", original_content)
        baseline_hash = hashlib.sha256(original_content).hexdigest()

        # Modify the file content on disk
        with open(file_path, "wb") as f:
            f.write(b"Sensor reading = 99.9")

        # Verify mismatch
        self.assertFalse(verify_file_integrity(file_path, baseline_hash))

        report = generate_integrity_report(file_path, baseline_hash)
        self.assertEqual(report["integrity_status"], IntegrityStatus.MODIFIED.value)
        self.assertTrue(report["is_modified"])
        self.assertNotEqual(report["actual_hash"], baseline_hash)
        self.assertIn("File contents differ", report["explanation"])

    # 4. Missing file (MISSING)
    def test_missing_file_handling(self):
        """Verify safe handling of a missing file without crashing."""
        missing_path = self.dir_path / "non_existent_file.dat"
        dummy_hash = "a" * 64

        self.assertFalse(verify_file_integrity(missing_path, dummy_hash))

        report = generate_integrity_report(missing_path, dummy_hash)
        self.assertEqual(report["integrity_status"], IntegrityStatus.MISSING.value)
        self.assertFalse(report["is_modified"])
        self.assertIsNone(report["actual_hash"])
        self.assertIn("File does not exist", report["explanation"])

    # 5. Invalid file path (e.g., directory or empty string)
    def test_invalid_file_path_handling(self):
        """Verify that passing a directory or empty path produces ERROR status safely."""
        dummy_hash = "b" * 64

        sub_dir = self.dir_path / "a_directory"
        sub_dir.mkdir()
        self.assertFalse(verify_file_integrity(sub_dir, dummy_hash))
        report_dir = generate_integrity_report(sub_dir, dummy_hash)
        self.assertEqual(report_dir["integrity_status"], IntegrityStatus.ERROR.value)
        self.assertIn("is a directory", report_dir["explanation"])

        self.assertFalse(verify_file_integrity("", dummy_hash))
        report_empty = generate_integrity_report("", dummy_hash)
        self.assertEqual(report_empty["integrity_status"], IntegrityStatus.ERROR.value)

    # 6. Invalid or malformed expected hash
    def test_invalid_malformed_expected_hash(self):
        """Verify that malformed hashes are rejected with ERROR without crashing."""
        content = b"Some valid content."
        file_path = self._create_temp_file("test.txt", content)

        invalid_hashes = [
            "too_short",
            "x" * 64,  # non-hexadecimal character 'x'
            "12345",
            "",
            None,
            "   ",
        ]

        for bad_hash in invalid_hashes:
            self.assertFalse(
                verify_file_integrity(file_path, bad_hash),
                f"Failed to reject invalid hash: {bad_hash}"
            )
            report = generate_integrity_report(file_path, bad_hash)
            self.assertEqual(
                report["integrity_status"],
                IntegrityStatus.ERROR.value,
                f"Expected ERROR status for bad hash: {bad_hash}"
            )
            self.assertFalse(report["is_modified"])
            self.assertIsNone(report["actual_hash"])

    # 7. Empty file
    def test_empty_file_hashing(self):
        """Verify hash of an empty file matches known SHA-256 standard digest."""
        file_path = self._create_temp_file("empty.bin", b"")
        known_empty_hash = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

        calculated = calculate_file_hash(file_path)
        self.assertEqual(calculated, known_empty_hash)
        self.assertTrue(verify_file_integrity(file_path, known_empty_hash))

        report = generate_integrity_report(file_path, known_empty_hash)
        self.assertEqual(report["integrity_status"], IntegrityStatus.INTACT.value)

    # 8. Large file with chunk-based reading
    def test_large_file_chunk_based_reading(self):
        """Verify that files larger than chunk size hash correctly via streaming."""
        large_chunk = b"VERITYOS_STREAMING_TEST_BLOCK_DATA_1234\n" * 3750  # ~150,000 bytes
        file_path = self._create_temp_file("large_file.dat", large_chunk)
        expected = hashlib.sha256(large_chunk).hexdigest().lower()

        calculated = calculate_file_hash(file_path, chunk_size=4096)
        self.assertEqual(calculated, expected)
        self.assertTrue(verify_file_integrity(file_path, expected, chunk_size=4096))

    # 9. Case differences in hexadecimal representation
    def test_case_differences_in_hash_comparison(self):
        """Verify case-insensitive hash comparison (uppercase vs lowercase)."""
        content = b"Case sensitivity check payload"
        file_path = self._create_temp_file("case.txt", content)
        lower_hash = hashlib.sha256(content).hexdigest().lower()
        upper_hash = lower_hash.upper()

        self.assertTrue(compare_hashes(lower_hash, upper_hash))
        self.assertTrue(compare_hashes(upper_hash, lower_hash))
        self.assertTrue(verify_file_integrity(file_path, upper_hash))

        report = generate_integrity_report(file_path, upper_hash)
        self.assertEqual(report["integrity_status"], IntegrityStatus.INTACT.value)

    # 10. Ensure baseline hashes are never overwritten
    def test_baseline_hash_never_overwritten(self):
        """Verify the caller's baseline hash reference is immutable and unchanged."""
        original_baseline = "A" * 64
        file_path = self._create_temp_file("immutable.txt", b"Random data")

        _ = verify_file_integrity(file_path, original_baseline)
        report = generate_integrity_report(file_path, original_baseline)

        self.assertEqual(original_baseline, "A" * 64)
        self.assertEqual(report["expected_hash"], original_baseline)

    # 11. Evidence item integration with IntegrityChecker class
    def test_evidence_item_integrity_workflow(self):
        """Verify check_evidence_integrity method with Evidence objects."""
        checker = IntegrityChecker()
        content = b"Evidence supporting claim C1"
        file_path = self._create_temp_file("evidence_doc.txt", content)
        valid_hash = hashlib.sha256(content).hexdigest()

        # Case A: Valid evidence item with matching local file
        ev_valid = Evidence(evidence_id="E1", sha256_hash=valid_hash)
        rep_a = checker.check_evidence_integrity(ev_valid, file_path=file_path)
        self.assertEqual(rep_a["integrity_status"], IntegrityStatus.INTACT.value)
        self.assertEqual(rep_a["evidence_id"], "E1")

        # Case B: Evidence item where file was modified
        ev_mod = Evidence(evidence_id="E2", sha256_hash="0" * 64)
        rep_b = checker.check_evidence_integrity(ev_mod, file_path=file_path)
        self.assertEqual(rep_b["integrity_status"], IntegrityStatus.MODIFIED.value)
        self.assertTrue(rep_b["is_modified"])

        # Case C: Evidence item with no baseline hash
        ev_no_hash = Evidence(evidence_id="E3")
        rep_c = checker.check_evidence_integrity(ev_no_hash, file_path=file_path)
        self.assertEqual(rep_c["integrity_status"], IntegrityStatus.MISSING.value)
        self.assertIn("No trusted baseline", rep_c["explanation"])

        # Case D: Evidence item with hash but no local file path
        ev_no_path = Evidence(evidence_id="E4", sha256_hash=valid_hash)
        rep_d = checker.check_evidence_integrity(ev_no_path, file_path=None)
        self.assertEqual(rep_d["integrity_status"], IntegrityStatus.MISSING.value)
        self.assertIn("no local file path was supplied", rep_d["explanation"])


class TestSourceChecker(unittest.TestCase):
    """Tests for source_checker.py validation, classification, and scoring."""

    def setUp(self):
        """Initialize SourceChecker instance."""
        self.checker = SourceChecker()

    # 1. Valid government source metadata
    def test_valid_government_source_metadata(self):
        """Verify government official source classification and high reliability."""
        evidence = {
            "evidence_id": "E_GOV_1",
            "source_url": "https://www.cdc.gov/data/report_2026.html",
            "source_title": "CDC Official Epidemiological Surveillance Report",
            "snippet": "National health survey results for 2026 indicate stability.",
            "source_type": "government",
        }
        report = self.checker.evaluate_source(evidence)
        self.assertEqual(report["source_category"], SourceCategory.GOVERNMENT_OFFICIAL.value)
        self.assertGreaterEqual(report["reliability_score"], 0.75)
        self.assertEqual(report["reliability_level"], ReliabilityLevel.HIGH.value)
        self.assertEqual(len(report["issues"]), 0)

    # 2. Academic source metadata
    def test_academic_source_metadata(self):
        """Verify academic research source classification and high reliability."""
        evidence = {
            "evidence_id": "E_ACAD_1",
            "source_url": "https://ai.stanford.edu/research/paper_2026.pdf",
            "source_title": "Stanford Autonomous Systems Laboratory Study",
            "snippet": "Experimental validation confirms multi-agent reliability.",
            "source_type": "academic",
        }
        report = self.checker.evaluate_source(evidence)
        self.assertEqual(report["source_category"], SourceCategory.ACADEMIC_RESEARCH.value)
        self.assertGreaterEqual(report["reliability_score"], 0.75)
        self.assertEqual(report["reliability_level"], ReliabilityLevel.HIGH.value)

    # 3. News source metadata
    def test_news_source_metadata(self):
        """Verify reputable news classification and scoring."""
        evidence = {
            "evidence_id": "E_NEWS_1",
            "source_url": "https://www.reuters.com/business/tech-report",
            "source_title": "Reuters Global Technology Sector Analysis",
            "snippet": "Quarterly technology sector investments rose by 14 percent.",
            "source_type": "news",
        }
        report = self.checker.evaluate_source(evidence)
        self.assertEqual(report["source_category"], SourceCategory.REPUTABLE_NEWS.value)
        self.assertGreaterEqual(report["reliability_score"], 0.70)
        self.assertEqual(report["reliability_level"], ReliabilityLevel.HIGH.value)

    # 4. General website metadata
    def test_general_website_metadata(self):
        """Verify general commercial/blog website classification and moderate score."""
        evidence = {
            "evidence_id": "E_WEB_1",
            "source_url": "https://techblog123.com/posts/ai-trends",
            "source_title": "Tech Enthusiast Opinion Blog Post",
            "snippet": "Observations on recent artificial intelligence milestones.",
            "source_type": "website",
        }
        report = self.checker.evaluate_source(evidence)
        self.assertEqual(report["source_category"], SourceCategory.GENERAL_WEBSITE.value)
        self.assertLess(report["reliability_score"], 0.75)
        self.assertIn(report["reliability_level"], (ReliabilityLevel.MEDIUM.value, ReliabilityLevel.LOW.value))

    # 5. Unknown source type
    def test_unknown_source_type(self):
        """Verify unknown source type is handled conservatively without inflation."""
        evidence = {
            "evidence_id": "E_UNK_1",
            "source_url": None,
            "source_title": "Unattributed Memorandum",
            "snippet": "Unverified claims without source reference.",
            "source_type": None,
        }
        report = self.checker.evaluate_source(evidence)
        self.assertEqual(report["source_category"], SourceCategory.UNKNOWN.value)
        self.assertLess(report["reliability_score"], 0.35)
        self.assertIn(report["reliability_level"], (ReliabilityLevel.LOW.value, ReliabilityLevel.UNKNOWN.value))

    # 6. Missing source URL
    def test_missing_source_url(self):
        """Verify missing source URL is penalized and noted in issues."""
        evidence = {
            "evidence_id": "E_NO_URL",
            "source_url": None,
            "source_title": "Academic Research Paper Title",
            "snippet": "Study excerpt without accompanying hyperlink.",
            "source_type": "academic",
        }
        report = self.checker.evaluate_source(evidence)
        self.assertTrue(any("Missing 'source_url'" in issue for issue in report["issues"]))
        ev_with_url = dict(evidence, source_url="https://mit.edu/paper")
        rep_with_url = self.checker.evaluate_source(ev_with_url)
        self.assertLess(report["reliability_score"], rep_with_url["reliability_score"])

    # 7. Missing source title
    def test_missing_source_title(self):
        """Verify missing source title is penalized and recorded in issues."""
        evidence = {
            "evidence_id": "E_NO_TITLE",
            "source_url": "https://www.cdc.gov/data",
            "source_title": None,
            "snippet": "Statistics excerpt.",
            "source_type": "government",
        }
        report = self.checker.evaluate_source(evidence)
        self.assertTrue(any("Missing or empty 'source_title'" in issue for issue in report["issues"]))

    # 8. Invalid URL format
    def test_invalid_url_format(self):
        """Verify syntactically malformed URLs are flagged in issues."""
        invalid_urls = ["not-a-valid-url", "ftp:///bad_schema", "http://", "https://"]
        for bad_url in invalid_urls:
            evidence = {
                "evidence_id": "E_BAD_URL",
                "source_url": bad_url,
                "source_title": "Some Title",
                "snippet": "Some snippet",
                "source_type": "website",
            }
            report = self.checker.evaluate_source(evidence)
            self.assertTrue(
                any("Invalid URL format" in issue or "Missing" in issue for issue in report["issues"]),
                f"Failed to flag bad URL: {bad_url}"
            )

    # 9. Missing evidence ID
    def test_missing_evidence_id(self):
        """Verify missing evidence_id triggers penalty and issue flag."""
        evidence = {
            "evidence_id": None,
            "source_url": "https://www.nature.com/articles/123",
            "source_title": "Nature Scientific Article",
            "snippet": "Peer-reviewed findings.",
            "source_type": "academic",
        }
        report = self.checker.evaluate_source(evidence)
        self.assertTrue(any("evidence_id" in issue for issue in report["issues"]))
        self.assertEqual(report["evidence_id"], "unknown")

    # 10. Empty evidence
    def test_empty_evidence(self):
        """Verify empty evidence item returns zero or conservative score and UNKNOWN level."""
        report = self.checker.evaluate_source({})
        self.assertEqual(report["evidence_id"], "unknown")
        self.assertEqual(report["source_category"], SourceCategory.UNKNOWN.value)
        self.assertLessEqual(report["reliability_score"], 0.20)
        self.assertEqual(report["reliability_level"], ReliabilityLevel.UNKNOWN.value)
        self.assertGreater(len(report["issues"]), 0)

    # 11. Dictionary input
    def test_dictionary_input(self):
        """Verify that standard Python dictionaries evaluate properly."""
        evidence_dict = {
            "evidence_id": "E_DICT_1",
            "source_url": "https://who.int/reports/global-health",
            "source_title": "World Health Organization Annual Review",
            "snippet": "Global health data indicators.",
            "source_type": "organization",
        }
        report = self.checker.evaluate_source(evidence_dict)
        self.assertEqual(report["evidence_id"], "E_DICT_1")
        self.assertEqual(report["source_category"], SourceCategory.ORGANIZATIONAL_INSTITUTIONAL.value)
        self.assertGreater(report["reliability_score"], 0.50)

    # 12. Pydantic Evidence input
    def test_pydantic_evidence_input(self):
        """Verify that Pydantic Evidence objects evaluate identically to dictionaries."""
        pydantic_ev = Evidence(
            evidence_id="E_PYD_1",
            source_url="https://who.int/reports/global-health",
            source_title="World Health Organization Annual Review",
            snippet="Global health data indicators.",
            source_type="organization",
        )
        report = self.checker.evaluate_source(pydantic_ev)
        self.assertEqual(report["evidence_id"], "E_PYD_1")
        self.assertEqual(report["source_category"], SourceCategory.ORGANIZATIONAL_INSTITUTIONAL.value)

    # 13. Reliability score boundaries
    def test_reliability_score_boundaries(self):
        """Verify reliability score is always strictly normalized between 0.0 and 1.0."""
        test_cases = [
            {},
            {"evidence_id": "E1"},
            {"evidence_id": "E2", "source_url": "https://gov.us", "source_title": "Official", "source_type": "government", "snippet": "Text"},
            {"evidence_id": "E3", "source_url": "bad_url", "source_title": "x", "source_type": "unknown"},
        ]
        for case in test_cases:
            score = calculate_source_reliability(case)
            self.assertGreaterEqual(score, 0.0, f"Score below 0 for case: {case}")
            self.assertLessEqual(score, 1.0, f"Score above 1 for case: {case}")

    # 14. Multiple evidence items
    def test_multiple_evidence_items(self):
        """Verify evaluate_sources batch method correctly aggregates metrics."""
        evidence_list = [
            {
                "evidence_id": "E1",
                "source_url": "https://cdc.gov/data",
                "source_title": "CDC Official Stats",
                "snippet": "Public health data.",
                "source_type": "government",
            },
            {
                "evidence_id": "E2",
                "source_url": "https://techblog.com/ai",
                "source_title": "Blog Article",
                "snippet": "Opinion piece.",
                "source_type": "website",
            },
            {
                "evidence_id": "E3",
                "source_url": None,
                "source_title": None,
                "snippet": None,
                "source_type": None,
            },
        ]
        batch_summary = self.checker.evaluate_sources(evidence_list)
        self.assertEqual(batch_summary["total_sources"], 3)
        self.assertIn("average_reliability_score", batch_summary)
        self.assertGreater(batch_summary["average_reliability_score"], 0.0)
        self.assertEqual(len(batch_summary["source_reports"]), 3)
        self.assertIn("reliability_distribution", batch_summary)
        self.assertIn("summary_level", batch_summary)

    # 15. Invalid input handling
    def test_invalid_input_handling(self):
        """Verify passing None or non-dictionary types does not crash."""
        for invalid_input in [None, 12345, "just a string", []]:
            report = self.checker.evaluate_source(invalid_input)
            self.assertEqual(report["evidence_id"], "unknown")
            self.assertEqual(report["source_category"], SourceCategory.UNKNOWN.value)
            self.assertLessEqual(report["reliability_score"], 0.20)

        empty_batch = self.checker.evaluate_sources(None)
        self.assertEqual(empty_batch["total_sources"], 0)


class TestFreshnessChecker(unittest.TestCase):
    """Tests for freshness_checker.py date parsing, age decay, categories, and batching."""

    def setUp(self):
        """Initialize fixed reference date and FreshnessChecker for deterministic testing."""
        self.ref_date = date(2026, 6, 1)
        self.ref_datetime = datetime(2026, 6, 1, 0, 0, 0, tzinfo=timezone.utc)
        self.checker = FreshnessChecker(reference_date=self.ref_date)

    # 1. Evidence published today
    def test_evidence_published_today(self):
        """Verify evidence published on the reference date is FRESH with score 1.0."""
        evidence = {
            "evidence_id": "E_TODAY",
            "publication_date": "2026-06-01",
        }
        report = self.checker.evaluate_evidence(evidence, reference_date=self.ref_date)
        self.assertEqual(report["freshness_status"], FreshnessStatus.FRESH.value)
        self.assertEqual(report["age_days"], 0)
        self.assertAlmostEqual(report["freshness_score"], 1.0, places=3)
        self.assertEqual(len(report["issues"]), 0)

    # 2. Evidence published 10 days ago
    def test_evidence_published_10_days_ago(self):
        """Verify evidence published 10 days ago is FRESH with partial decay."""
        pub = (self.ref_date - timedelta(days=10)).isoformat()
        evidence = {"evidence_id": "E_10D", "publication_date": pub}
        report = self.checker.evaluate_evidence(evidence, reference_date=self.ref_date)
        self.assertEqual(report["freshness_status"], FreshnessStatus.FRESH.value)
        self.assertEqual(report["age_days"], 10)
        self.assertAlmostEqual(report["freshness_score"], 0.9333, places=3)

    # 3. Evidence published 30 days ago (Fresh boundary)
    def test_evidence_published_30_days_ago(self):
        """Verify evidence published exactly 30 days ago is FRESH at lower fresh bound (0.80)."""
        pub = (self.ref_date - timedelta(days=30)).isoformat()
        evidence = {"evidence_id": "E_30D", "publication_date": pub}
        report = self.checker.evaluate_evidence(evidence, reference_date=self.ref_date)
        self.assertEqual(report["freshness_status"], FreshnessStatus.FRESH.value)
        self.assertEqual(report["age_days"], 30)
        self.assertAlmostEqual(report["freshness_score"], 0.80, places=3)

    # 4. Evidence published 31 days ago (Aging entry)
    def test_evidence_published_31_days_ago(self):
        """Verify evidence published 31 days ago transitions to AGING status."""
        pub = (self.ref_date - timedelta(days=31)).isoformat()
        evidence = {"evidence_id": "E_31D", "publication_date": pub}
        report = self.checker.evaluate_evidence(evidence, reference_date=self.ref_date)
        self.assertEqual(report["freshness_status"], FreshnessStatus.AGING.value)
        self.assertEqual(report["age_days"], 31)
        self.assertLess(report["freshness_score"], 0.80)
        self.assertGreater(report["freshness_score"], 0.75)

    # 5. Evidence published 180 days ago (Aging boundary)
    def test_evidence_published_180_days_ago(self):
        """Verify evidence published exactly 180 days ago is AGING at lower bound (0.40)."""
        pub = (self.ref_date - timedelta(days=180)).isoformat()
        evidence = {"evidence_id": "E_180D", "publication_date": pub}
        report = self.checker.evaluate_evidence(evidence, reference_date=self.ref_date)
        self.assertEqual(report["freshness_status"], FreshnessStatus.AGING.value)
        self.assertEqual(report["age_days"], 180)
        self.assertAlmostEqual(report["freshness_score"], 0.40, places=3)

    # 6. Evidence published more than 180 days ago (Stale entry)
    def test_evidence_published_more_than_180_days_ago(self):
        """Verify evidence published 200 days ago transitions to STALE status."""
        pub = (self.ref_date - timedelta(days=200)).isoformat()
        evidence = {"evidence_id": "E_200D", "publication_date": pub}
        report = self.checker.evaluate_evidence(evidence, reference_date=self.ref_date)
        self.assertEqual(report["freshness_status"], FreshnessStatus.STALE.value)
        self.assertEqual(report["age_days"], 200)
        self.assertLess(report["freshness_score"], 0.40)
        self.assertGreater(report["freshness_score"], 0.0)

    # 7. Missing publication date
    def test_missing_publication_date(self):
        """Verify missing publication date results in UNKNOWN status and score=None."""
        evidence = {"evidence_id": "E_NO_DATE", "publication_date": None}
        report = self.checker.evaluate_evidence(evidence, reference_date=self.ref_date)
        self.assertEqual(report["freshness_status"], FreshnessStatus.UNKNOWN.value)
        self.assertIsNone(report["freshness_score"])
        self.assertIsNone(report["age_days"])
        self.assertTrue(any("Missing publication date" in issue for issue in report["issues"]))

    # 8. Invalid date string
    def test_invalid_date_string(self):
        """Verify unparseable date strings result in INVALID_DATE status and score=None."""
        evidence = {"evidence_id": "E_BAD_DATE", "publication_date": "invalid-date-format-xyz"}
        report = self.checker.evaluate_evidence(evidence, reference_date=self.ref_date)
        self.assertEqual(report["freshness_status"], FreshnessStatus.INVALID_DATE.value)
        self.assertIsNone(report["freshness_score"])
        self.assertIsNone(report["age_days"])
        self.assertTrue(any("Invalid publication date" in issue for issue in report["issues"]))

    # 9. Future publication date
    def test_future_publication_date(self):
        """Verify future publication dates are flagged as FUTURE_DATED with score=None."""
        future_pub = (self.ref_date + timedelta(days=5)).isoformat()
        evidence = {"evidence_id": "E_FUTURE", "publication_date": future_pub}
        report = self.checker.evaluate_evidence(evidence, reference_date=self.ref_date)
        self.assertEqual(report["freshness_status"], FreshnessStatus.FUTURE_DATED.value)
        self.assertIsNone(report["freshness_score"])
        self.assertEqual(report["age_days"], -5)
        self.assertTrue(any("future" in issue.lower() for issue in report["issues"]))

    # 10. ISO datetime
    def test_iso_datetime(self):
        """Verify standard ISO 8601 datetime format parsing."""
        pub_iso = "2026-05-15T14:30:00"
        evidence = {"evidence_id": "E_ISO", "publication_date": pub_iso}
        report = self.checker.evaluate_evidence(evidence, reference_date=self.ref_date)
        self.assertEqual(report["freshness_status"], FreshnessStatus.FRESH.value)
        self.assertEqual(report["age_days"], 17)
        self.assertIsNotNone(report["freshness_score"])

    # 11. Timezone-aware datetime string
    def test_timezone_aware_datetime(self):
        """Verify timezone-aware ISO string parsing (+05:30 and Z)."""
        pub_tz = "2026-05-15T14:30:00+05:30"
        evidence = {"evidence_id": "E_TZ", "publication_date": pub_tz}
        report = self.checker.evaluate_evidence(evidence, reference_date=self.ref_date)
        self.assertEqual(report["freshness_status"], FreshnessStatus.FRESH.value)
        self.assertEqual(report["age_days"], 17)

        pub_z = "2026-05-15T14:30:00Z"
        rep_z = self.checker.evaluate_evidence({"evidence_id": "E_Z", "publication_date": pub_z}, reference_date=self.ref_date)
        self.assertEqual(rep_z["freshness_status"], FreshnessStatus.FRESH.value)

    # 12. Python date object
    def test_python_date_object(self):
        """Verify handling of native datetime.date objects."""
        evidence = {"evidence_id": "E_DATE_OBJ", "publication_date": date(2026, 5, 20)}
        report = self.checker.evaluate_evidence(evidence, reference_date=self.ref_date)
        self.assertEqual(report["freshness_status"], FreshnessStatus.FRESH.value)
        self.assertEqual(report["age_days"], 12)

    # 13. Python datetime object
    def test_python_datetime_object(self):
        """Verify handling of native datetime.datetime objects (tz-naive and tz-aware)."""
        dt_aware = datetime(2026, 5, 20, 10, 0, 0, tzinfo=timezone.utc)
        evidence = {"evidence_id": "E_DT_OBJ", "publication_date": dt_aware}
        report = self.checker.evaluate_evidence(evidence, reference_date=self.ref_date)
        self.assertEqual(report["freshness_status"], FreshnessStatus.FRESH.value)
        self.assertEqual(report["age_days"], 12)

    # 14. Dictionary input
    def test_dictionary_input(self):
        """Verify standard dictionary input formats."""
        evidence_dict = {
            "evidence_id": "E_DICT",
            "publication_date": "2026-05-01",
            "source_title": "Monthly Economic Bulletin",
        }
        report = self.checker.evaluate_evidence(evidence_dict, reference_date=self.ref_date)
        self.assertEqual(report["evidence_id"], "E_DICT")
        self.assertEqual(report["freshness_status"], FreshnessStatus.AGING.value)

    # 15. Pydantic Evidence input
    def test_pydantic_evidence_input(self):
        """Verify Pydantic Evidence model input evaluates identically."""
        pyd_ev = Evidence(
            evidence_id="E_PYD",
            publication_date="2026-05-01",
            source_title="Monthly Economic Bulletin",
        )
        report = self.checker.evaluate_evidence(pyd_ev, reference_date=self.ref_date)
        self.assertEqual(report["evidence_id"], "E_PYD")
        self.assertEqual(report["freshness_status"], FreshnessStatus.AGING.value)

    # 16. Custom freshness thresholds
    def test_custom_freshness_thresholds(self):
        """Verify custom age threshold configuration (e.g. 7 days fresh, 30 days aging)."""
        custom_checker = FreshnessChecker(
            fresh_max_days=7,
            aging_max_days=30,
            reference_date=self.ref_date
        )
        pub = (self.ref_date - timedelta(days=10)).isoformat()
        evidence = {"evidence_id": "E_CUSTOM", "publication_date": pub}
        report = custom_checker.evaluate_evidence(evidence)
        self.assertEqual(report["freshness_status"], FreshnessStatus.AGING.value)

    # 17. Batch evaluation
    def test_batch_evaluation(self):
        """Verify evaluate_evidences batch function aggregates counts and averages."""
        evidence_list = [
            {"evidence_id": "E1", "publication_date": "2026-06-01"},  # Fresh (age 0) -> score 1.0
            {"evidence_id": "E2", "publication_date": "2026-05-01"},  # Aging (age 31) -> score ~0.787
            {"evidence_id": "E3", "publication_date": "2025-06-01"},  # Stale (age 365) -> score 0.0
            {"evidence_id": "E4", "publication_date": None},          # Unknown -> score None
            {"evidence_id": "E5", "publication_date": "2026-07-01"},  # Future -> score None
            {"evidence_id": "E6", "publication_date": "not-a-date"},  # Invalid -> score None
        ]
        batch = self.checker.evaluate_evidences(evidence_list, reference_date=self.ref_date)
        self.assertEqual(batch["total_evidence_count"], 6)
        self.assertEqual(batch["fresh_count"], 1)
        self.assertEqual(batch["aging_count"], 1)
        self.assertEqual(batch["stale_count"], 1)
        self.assertEqual(batch["unknown_count"], 1)
        self.assertEqual(batch["future_count"], 1)
        self.assertEqual(batch["invalid_count"], 1)
        self.assertEqual(batch["available_scores_count"], 3)
        self.assertIsNotNone(batch["average_freshness_score"])

    # 18. Empty evidence list
    def test_empty_evidence_list(self):
        """Verify empty evidence list returns safe zero counts and score=None."""
        batch = self.checker.evaluate_evidences([], reference_date=self.ref_date)
        self.assertEqual(batch["total_evidence_count"], 0)
        self.assertEqual(batch["available_scores_count"], 0)
        self.assertIsNone(batch["average_freshness_score"])
        self.assertEqual(len(batch["reports"]), 0)

    # 19. Invalid input handling
    def test_invalid_input_handling(self):
        """Verify non-dictionary inputs are handled safely without crashing."""
        for bad_item in [None, 12345, "just a string", []]:
            report = self.checker.evaluate_evidence(bad_item, reference_date=self.ref_date)
            self.assertEqual(report["evidence_id"], "unknown")
            self.assertEqual(report["freshness_status"], FreshnessStatus.UNKNOWN.value)
            self.assertIsNone(report["freshness_score"])

        batch = self.checker.evaluate_evidences(None)
        self.assertEqual(batch["total_evidence_count"], 0)

    # 20. Average score calculation excluding unavailable scores
    def test_average_score_excluding_unavailable(self):
        """Verify average freshness score excludes unavailable None scores without score inflation."""
        evidence_list = [
            {"evidence_id": "E1", "publication_date": "2026-06-01"},  # score = 1.00
            {"evidence_id": "E2", "publication_date": None},          # score = None (must not be treated as 1.0 or 0.0)
            {"evidence_id": "E3", "publication_date": "bad_date"},     # score = None
        ]
        batch = self.checker.evaluate_evidences(evidence_list, reference_date=self.ref_date)
        self.assertEqual(batch["total_evidence_count"], 3)
        self.assertEqual(batch["available_scores_count"], 1)
        self.assertAlmostEqual(batch["average_freshness_score"], 1.0, places=3)


class TestConsistencyChecker(unittest.TestCase):
    """Tests for consistency_checker.py numerical normalization, units, dates, periods, and batching."""

    def setUp(self):
        """Initialize ConsistencyChecker."""
        self.checker = ConsistencyChecker()

    # 1. Equal numeric values
    def test_equal_numeric_values(self):
        """Verify identical numbers report CONSISTENT with zero difference."""
        res = compare_numeric_values(50, 50)
        self.assertTrue(res["is_equivalent"])
        self.assertEqual(res["comparison_status"], ValueComparisonStatus.CONSISTENT.value)
        self.assertEqual(res["difference"], 0.0)

    # 2. Different numeric values
    def test_different_numeric_values(self):
        """Verify differing numbers report INCONSISTENT with correct difference."""
        res = compare_numeric_values(50, 60)
        self.assertFalse(res["is_equivalent"])
        self.assertEqual(res["comparison_status"], ValueComparisonStatus.INCONSISTENT.value)
        self.assertEqual(res["difference"], 10.0)

    # 3. Equivalent values in convertible units
    def test_equivalent_values_in_convertible_units(self):
        """Verify equivalent values across convertible units (50 kg == 50,000 g, 2 km == 2000 m)."""
        # Mass: 50 kg vs 50000 g
        res_mass = compare_numeric_values(50, 50000, unit1="kg", unit2="g")
        self.assertTrue(res_mass["is_equivalent"])
        self.assertEqual(res_mass["comparison_status"], ValueComparisonStatus.CONSISTENT.value)
        self.assertEqual(res_mass["canonical_unit"], "kg")
        self.assertAlmostEqual(res_mass["difference"], 0.0, places=5)

        # Length: 2 km vs 2000 m
        res_len = compare_numeric_values(2, 2000, unit1="km", unit2="m")
        self.assertTrue(res_len["is_equivalent"])
        self.assertEqual(res_len["comparison_status"], ValueComparisonStatus.CONSISTENT.value)
        self.assertEqual(res_len["canonical_unit"], "m")
        self.assertAlmostEqual(res_len["difference"], 0.0, places=5)

    # 4. Incompatible units
    def test_incompatible_units(self):
        """Verify values with incompatible units (e.g. mass vs length, currencies) report INCOMPATIBLE_UNITS."""
        res_diff_dim = compare_numeric_values(50, 50, unit1="kg", unit2="km")
        self.assertFalse(res_diff_dim["is_equivalent"])
        self.assertEqual(res_diff_dim["comparison_status"], ValueComparisonStatus.INCOMPATIBLE_UNITS.value)

        # Currencies: USD vs EUR cannot be converted without exchange rates
        res_currency = compare_numeric_values(100, 100, unit1="usd", unit2="eur")
        self.assertFalse(res_currency["is_equivalent"])
        self.assertEqual(res_currency["comparison_status"], ValueComparisonStatus.INCOMPATIBLE_UNITS.value)

    # 5. Invalid numeric input
    def test_invalid_numeric_input(self):
        """Verify non-numeric string inputs report INVALID_VALUE without crashing."""
        res = compare_numeric_values("abc", 50)
        self.assertFalse(res["is_equivalent"])
        self.assertEqual(res["comparison_status"], ValueComparisonStatus.INVALID_VALUE.value)
        self.assertIn("Invalid numeric input", res["explanation"])

    # 6. Missing numeric input
    def test_missing_numeric_input(self):
        """Verify None values report MISSING_VALUE without crashing."""
        res = compare_numeric_values(None, 50)
        self.assertFalse(res["is_equivalent"])
        self.assertEqual(res["comparison_status"], ValueComparisonStatus.MISSING_VALUE.value)

    # 7. Matching dates
    def test_matching_dates(self):
        """Verify identical dates report MATCHING with 0 days difference."""
        res = compare_dates("2026-05-01", "2026-05-01")
        self.assertTrue(res["is_matching"])
        self.assertEqual(res["comparison_status"], DateComparisonStatus.MATCHING.value)
        self.assertEqual(res["difference_days"], 0)

    # 8. Different dates
    def test_different_dates(self):
        """Verify distinct dates report DIFFERENT with accurate days difference."""
        res = compare_dates("2026-05-01", "2026-05-15")
        self.assertFalse(res["is_matching"])
        self.assertEqual(res["comparison_status"], DateComparisonStatus.DIFFERENT.value)
        self.assertEqual(res["difference_days"], 14)

    # 9. Invalid dates
    def test_invalid_dates(self):
        """Verify unparseable date strings report INVALID without crashing."""
        res = compare_dates("not_a_date", "2026-05-01")
        self.assertFalse(res["is_matching"])
        self.assertEqual(res["comparison_status"], DateComparisonStatus.INVALID.value)

    # 10. Missing dates
    def test_missing_dates(self):
        """Verify missing dates (None) report MISSING without crashing."""
        res = compare_dates(None, "2026-05-01")
        self.assertFalse(res["is_matching"])
        self.assertEqual(res["comparison_status"], DateComparisonStatus.MISSING.value)

    # 11. Matching reporting periods
    def test_matching_reporting_periods(self):
        """Verify equivalent period formats (Q1 2024 vs 2024-Q1) report SAME_PERIOD."""
        res_q = compare_reporting_periods("Q1 2024", "2024-Q1")
        self.assertTrue(res_q["is_same_period"])
        self.assertEqual(res_q["comparison_status"], PeriodComparisonStatus.SAME_PERIOD.value)

        res_fy = compare_reporting_periods("FY2023", "FY 2023")
        self.assertTrue(res_fy["is_same_period"])
        self.assertEqual(res_fy["comparison_status"], PeriodComparisonStatus.SAME_PERIOD.value)

    # 12. Different reporting periods
    def test_different_reporting_periods(self):
        """Verify distinct periods (Q1 2024 vs Q2 2024) report DIFFERENT_PERIODS and not contradictory."""
        res = compare_reporting_periods("Q1 2024", "Q2 2024")
        self.assertFalse(res["is_same_period"])
        self.assertEqual(res["comparison_status"], PeriodComparisonStatus.DIFFERENT_PERIODS.value)
        self.assertIn("separate reporting periods", res["explanation"])

    # 13. Missing reporting periods
    def test_missing_reporting_periods(self):
        """Verify missing reporting periods report MISSING without crashing."""
        res = compare_reporting_periods(None, "Q1 2024")
        self.assertFalse(res["is_same_period"])
        self.assertEqual(res["comparison_status"], PeriodComparisonStatus.MISSING.value)

    # 14. Empty evidence
    def test_empty_evidence(self):
        """Verify empty evidence returns INSUFFICIENT status with score=None."""
        rep = self.checker.evaluate_claim(claim={"claim_id": "C1"}, evidence_items=[])
        self.assertEqual(rep["consistency_status"], ConsistencyStatus.INSUFFICIENT.value)
        self.assertIsNone(rep["consistency_score"])
        self.assertEqual(rep["comparison_count"], 0)

    # 15. Multiple evidence items with structured data
    def test_multiple_evidence_items(self):
        """Verify multiple structured items evaluate pairwise consistency."""
        structured = [
            {"evidence_id": "E1", "metric": "revenue", "value": 100, "unit": "kg", "period": "2024"},
            {"evidence_id": "E2", "metric": "revenue", "value": 100000, "unit": "g", "period": "2024"}, # consistent with E1
            {"evidence_id": "E3", "metric": "revenue", "value": 150, "unit": "kg", "period": "2024"},    # inconsistent
        ]
        rep = self.checker.evaluate_claim(claim={"claim_id": "C1"}, structured_data=structured)
        # Pairwise comparisons: (E1, E2)=consistent, (E1, E3)=inconsistent, (E2, E3)=inconsistent
        self.assertEqual(rep["comparison_count"], 3)
        self.assertEqual(rep["consistent_count"], 1)
        self.assertEqual(rep["inconsistent_count"], 2)
        self.assertEqual(rep["consistency_status"], ConsistencyStatus.MIXED.value)
        self.assertAlmostEqual(rep["consistency_score"], 1 / 3, places=3)

    # 16. Unknown consistency status
    def test_unknown_consistency_status(self):
        """Verify items with only incompatible units result in UNKNOWN status and score=None."""
        structured = [
            {"evidence_id": "E1", "metric": "output", "value": 100, "unit": "kg"},
            {"evidence_id": "E2", "metric": "output", "value": 100, "unit": "km"},
        ]
        rep = self.checker.evaluate_claim(claim={"claim_id": "C2"}, structured_data=structured)
        self.assertEqual(rep["comparison_count"], 1)
        self.assertEqual(rep["unknown_count"], 1)
        self.assertEqual(rep["consistency_status"], ConsistencyStatus.UNKNOWN.value)
        self.assertIsNone(rep["consistency_score"])

    # 17. Consistency score boundaries
    def test_consistency_score_boundaries(self):
        """Verify consistency score is strictly bounded in [0.0, 1.0] or None."""
        cases = [
            # 100% consistent
            [{"metric": "m", "value": 10}, {"metric": "m", "value": 10}],
            # 100% inconsistent
            [{"metric": "m", "value": 10}, {"metric": "m", "value": 20}],
            # Incompatible units
            [{"metric": "m", "value": 10, "unit": "kg"}, {"metric": "m", "value": 10, "unit": "km"}],
        ]
        for c in cases:
            rep = self.checker.evaluate_claim(claim={"claim_id": "C"}, structured_data=c)
            if rep["consistency_score"] is not None:
                self.assertGreaterEqual(rep["consistency_score"], 0.0)
                self.assertLessEqual(rep["consistency_score"], 1.0)

    # 18. No comparisons available
    def test_no_comparisons_available(self):
        """Verify when no comparisons are available score is None rather than 1.0."""
        rep = self.checker.evaluate_claim(
            claim={"claim_id": "C1"},
            evidence_items=[{"evidence_id": "E1", "snippet": "Text only with no structured numbers."}]
        )
        self.assertIsNone(rep["consistency_score"])
        self.assertEqual(rep["consistency_status"], ConsistencyStatus.INSUFFICIENT.value)

    # 19. Dictionary inputs
    def test_dictionary_inputs(self):
        """Verify standard dictionary inputs evaluate properly."""
        claim_dict = {"claim_id": "C_DICT", "claim_text": "Sample claim"}
        structured = [
            {"evidence_id": "E1", "metric": "speed", "value": 60, "unit": "km"},
            {"evidence_id": "E2", "metric": "speed", "value": 60, "unit": "km"},
        ]
        rep = self.checker.evaluate_claim(claim=claim_dict, structured_data=structured)
        self.assertEqual(rep["claim_id"], "C_DICT")
        self.assertEqual(rep["consistency_status"], ConsistencyStatus.CONSISTENT.value)
        self.assertEqual(rep["consistency_score"], 1.0)

    # 20. Batch evaluation
    def test_batch_evaluation(self):
        """Verify evaluate_claims batch method aggregates counts and scores across multiple claims."""
        claims = [
            {"claim_id": "C1", "claim_text": "Claim 1"},
            {"claim_id": "C2", "claim_text": "Claim 2"},
            {"claim_id": "C3", "claim_text": "Claim 3"},
        ]
        structured_map = {
            "C1": [{"metric": "m", "value": 10}, {"metric": "m", "value": 10}], # consistent (1.0)
            "C2": [{"metric": "m", "value": 10}, {"metric": "m", "value": 90}], # inconsistent (0.0)
            "C3": [],                                                             # insufficient (None)
        }
        batch = self.checker.evaluate_claims(claims=claims, structured_data_map=structured_map)
        self.assertEqual(batch["total_claims"], 3)
        self.assertEqual(batch["consistent_claims"], 1)
        self.assertEqual(batch["inconsistent_claims"], 1)
        self.assertEqual(batch["insufficient_claims"], 1)
        self.assertEqual(batch["available_scores_count"], 2)
        # Average must be (1.0 + 0.0) / 2 = 0.50
        self.assertAlmostEqual(batch["average_consistency_score"], 0.50, places=3)

    # 21. Tolerance handling
    def test_tolerance_handling(self):
        """Verify comparison tolerance allows small differences to be evaluated as consistent."""
        # 50.05 vs 50.00
        res_strict = compare_numeric_values(50.05, 50.00, tolerance=0.01)
        self.assertFalse(res_strict["is_equivalent"])
        self.assertEqual(res_strict["comparison_status"], ValueComparisonStatus.INCONSISTENT.value)

        res_tolerant = compare_numeric_values(50.05, 50.00, tolerance=0.10)
        self.assertTrue(res_tolerant["is_equivalent"])
        self.assertEqual(res_tolerant["comparison_status"], ValueComparisonStatus.CONSISTENT.value)

    # 22. Invalid input resilience
    def test_invalid_input_resilience(self):
        """Verify passing None or non-dictionary types does not crash the checker."""
        for bad_input in [None, 12345, "invalid", []]:
            rep = self.checker.evaluate_claim(claim=bad_input)
            self.assertIsNone(rep["consistency_score"])
            self.assertEqual(rep["consistency_status"], ConsistencyStatus.INSUFFICIENT.value)

        empty_batch = self.checker.evaluate_claims(None)
        self.assertEqual(empty_batch["total_claims"], 0)


class TestTrustScoringEngine(unittest.TestCase):
    """Unit and integration tests for the Trust Scoring Engine (scoring.py)."""

    def setUp(self):
        """Set up standard scorers and dimension scores for tests."""
        self.scorer = TrustScorer()
        self.full_scores = {
            "source_quality": 0.90,
            "evidence_support": 0.80,
            "freshness": 0.70,
            "corroboration": 0.85,
            "consistency": 0.95,
            "data_quality": 1.00,
        }

    # 1. All 6 dimensions available
    def test_all_six_dimensions_available(self):
        """Verify weighted aggregation when all 6 trust dimensions are available."""
        # Expected:
        # 0.90*0.25 + 0.80*0.20 + 0.70*0.15 + 0.85*0.20 + 0.95*0.10 + 1.00*0.10
        # = 0.225 + 0.160 + 0.105 + 0.170 + 0.095 + 0.100 = 0.8550
        result = self.scorer.score(self.full_scores)

        self.assertEqual(result["status"], ScoringStatus.SUCCESS.value)
        self.assertAlmostEqual(result["overall_trust_score"], 0.8550, places=4)
        self.assertEqual(result["coverage_ratio"], 1.0)
        self.assertAlmostEqual(result["available_weight"], 1.0, places=4)
        self.assertEqual(len(result["available_dimensions"]), 6)
        self.assertEqual(len(result["unavailable_dimensions"]), 0)
        self.assertEqual(len(result["validation_errors"]), 0)

    # 2. 1 dimension unavailable (weight renormalization)
    def test_one_dimension_unavailable_renormalization(self):
        """Verify that an unavailable dimension (None) is excluded and weights are renormalized."""
        scores = dict(self.full_scores)
        scores["freshness"] = None  # Freshness weight 0.15 excluded

        result = self.scorer.score(scores)

        self.assertEqual(result["status"], ScoringStatus.SUCCESS.value)
        # Available weights sum = 1.00 - 0.15 = 0.85
        self.assertAlmostEqual(result["available_weight"], 0.85, places=4)
        self.assertAlmostEqual(result["coverage_ratio"], 0.85, places=4)
        self.assertIn("freshness", result["unavailable_dimensions"])
        self.assertEqual(len(result["available_dimensions"]), 5)

        # Expected sum: 0.8550 - (0.70 * 0.15) = 0.8550 - 0.1050 = 0.7500
        # Renormalized score: 0.7500 / 0.85 = 0.8823529... -> 0.8824
        expected_score = round(0.7500 / 0.85, 4)
        self.assertAlmostEqual(result["overall_trust_score"], expected_score, places=4)

    # 3. Multiple dimensions unavailable
    def test_multiple_dimensions_unavailable(self):
        """Verify correct score calculation when multiple dimensions are None."""
        partial_scores = {
            "source_quality": 0.80,    # weight 0.25
            "evidence_support": 0.60,  # weight 0.20
            "freshness": None,
            "corroboration": None,
            "consistency": None,
            "data_quality": None,
        }
        result = self.scorer.score(partial_scores)

        self.assertEqual(result["status"], ScoringStatus.SUCCESS.value)
        # Available weight: 0.25 + 0.20 = 0.45
        self.assertAlmostEqual(result["available_weight"], 0.45, places=4)
        self.assertAlmostEqual(result["coverage_ratio"], 0.45, places=4)
        # Weighted sum: (0.80 * 0.25) + (0.60 * 0.20) = 0.20 + 0.12 = 0.32
        # Renormalized: 0.32 / 0.45 = 0.711111... -> 0.7111
        expected = round(0.32 / 0.45, 4)
        self.assertAlmostEqual(result["overall_trust_score"], expected, places=4)
        self.assertEqual(len(result["available_dimensions"]), 2)
        self.assertEqual(len(result["unavailable_dimensions"]), 4)

    # 4. All dimensions unavailable (INSUFFICIENT_DATA)
    def test_all_dimensions_unavailable(self):
        """Verify that when all dimensions are None, status is INSUFFICIENT_DATA and score is None."""
        all_none = {dim: None for dim in DEFAULT_WEIGHTS.keys()}
        result = self.scorer.score(all_none)

        self.assertEqual(result["status"], ScoringStatus.INSUFFICIENT_DATA.value)
        self.assertIsNone(result["overall_trust_score"])
        self.assertEqual(result["coverage_ratio"], 0.0)
        self.assertEqual(result["available_weight"], 0.0)
        self.assertEqual(len(result["available_dimensions"]), 0)
        self.assertEqual(len(result["unavailable_dimensions"]), 6)

    # 5. Correct weighted average calculation
    def test_correct_weighted_average_calculation(self):
        """Directly verify calculate_weighted_score returns exact expected float values."""
        score = calculate_weighted_score(self.full_scores, DEFAULT_WEIGHTS)
        self.assertAlmostEqual(score, 0.8550, places=4)

    # 6. Correct weight renormalization relative ratios
    def test_weight_renormalization_preserves_ratios(self):
        """Verify that renormalizing over a subset of weights preserves relative dimensional proportions."""
        # Consider source_quality (0.25) and consistency (0.10). Ratio is 2.5:1.
        subset = {
            "source_quality": 1.0,
            "evidence_support": None,
            "freshness": None,
            "corroboration": None,
            "consistency": 0.0,
            "data_quality": None,
        }
        # Expected: (1.0 * 0.25 + 0.0 * 0.10) / (0.25 + 0.10) = 0.25 / 0.35 = 0.7143
        result = self.scorer.score(subset)
        expected = round(0.25 / 0.35, 4)
        self.assertAlmostEqual(result["overall_trust_score"], expected, places=4)

    # 7. Correct coverage calculation
    def test_coverage_calculation(self):
        """Direct unit test of calculate_trust_coverage helper."""
        test_scores = {
            "source_quality": 0.8,
            "freshness": 0.5,
        }
        cov = calculate_trust_coverage(test_scores, DEFAULT_WEIGHTS)
        # source_quality=0.25, freshness=0.15 -> sum 0.40
        self.assertAlmostEqual(cov["available_weight"], 0.40, places=4)
        self.assertAlmostEqual(cov["total_weight"], 1.00, places=4)
        self.assertAlmostEqual(cov["coverage_ratio"], 0.40, places=4)
        self.assertCountEqual(cov["available_dimensions"], ["source_quality", "freshness"])
        self.assertEqual(len(cov["unavailable_dimensions"]), 4)

    # 8. Score of 0.0 boundary
    def test_boundary_score_zero(self):
        """Verify that all dimensions evaluated at 0.0 correctly produces an overall score of 0.0."""
        zero_scores = {dim: 0.0 for dim in DEFAULT_WEIGHTS.keys()}
        result = self.scorer.score(zero_scores)
        self.assertEqual(result["status"], ScoringStatus.SUCCESS.value)
        self.assertEqual(result["overall_trust_score"], 0.0)

    # 9. Score of 1.0 boundary
    def test_boundary_score_one(self):
        """Verify that all dimensions evaluated at 1.0 correctly produces an overall score of 1.0."""
        perfect_scores = {dim: 1.0 for dim in DEFAULT_WEIGHTS.keys()}
        result = self.scorer.score(perfect_scores)
        self.assertEqual(result["status"], ScoringStatus.SUCCESS.value)
        self.assertEqual(result["overall_trust_score"], 1.0)

    # 10. Invalid negative score (< 0)
    def test_invalid_negative_score(self):
        """Verify that negative dimension scores trigger validation error."""
        invalid_scores = dict(self.full_scores)
        invalid_scores["source_quality"] = -0.25
        result = self.scorer.score(invalid_scores)

        self.assertEqual(result["status"], ScoringStatus.VALIDATION_ERROR.value)
        self.assertIsNone(result["overall_trust_score"])
        self.assertTrue(any("out of bounds" in err for err in result["validation_errors"]))

    # 11. Invalid score greater than 1.0 (> 1)
    def test_invalid_score_greater_than_one(self):
        """Verify that dimension scores exceeding 1.0 trigger validation error."""
        invalid_scores = dict(self.full_scores)
        invalid_scores["consistency"] = 1.05
        result = self.scorer.score(invalid_scores)

        self.assertEqual(result["status"], ScoringStatus.VALIDATION_ERROR.value)
        self.assertIsNone(result["overall_trust_score"])
        self.assertTrue(any("out of bounds" in err for err in result["validation_errors"]))

    # 12. Non-numeric score (type error / boolean)
    def test_non_numeric_and_boolean_rejection(self):
        """Verify strings, lists, and booleans are rejected as invalid scores."""
        # String rejection
        bad_str = dict(self.full_scores)
        bad_str["freshness"] = "high"
        res_str = self.scorer.score(bad_str)
        self.assertEqual(res_str["status"], ScoringStatus.VALIDATION_ERROR.value)
        self.assertTrue(any("numeric" in err for err in res_str["validation_errors"]))

        # Boolean rejection (Python bool is subclass of int; must be strictly checked)
        bad_bool = dict(self.full_scores)
        bad_bool["freshness"] = True
        res_bool = self.scorer.score(bad_bool)
        self.assertEqual(res_bool["status"], ScoringStatus.VALIDATION_ERROR.value)
        self.assertTrue(any("boolean" in err for err in res_bool["validation_errors"]))

    # 13. NaN and infinity values
    def test_nan_and_infinity_rejection(self):
        """Verify math.nan and math.inf trigger validation errors."""
        import math
        bad_nan = dict(self.full_scores)
        bad_nan["data_quality"] = float("nan")
        res_nan = self.scorer.score(bad_nan)
        self.assertEqual(res_nan["status"], ScoringStatus.VALIDATION_ERROR.value)
        self.assertTrue(any("finite" in err for err in res_nan["validation_errors"]))

        bad_inf = dict(self.full_scores)
        bad_inf["data_quality"] = float("inf")
        res_inf = self.scorer.score(bad_inf)
        self.assertEqual(res_inf["status"], ScoringStatus.VALIDATION_ERROR.value)
        self.assertTrue(any("finite" in err for err in res_inf["validation_errors"]))

    # 14. Missing dimension in input dictionary
    def test_missing_dimension_in_input_dict(self):
        """Verify that partially supplied dictionaries safely treat omitted dimensions as unavailable (None)."""
        partial_dict = {
            "source_quality": 0.80,
            "consistency": 0.90,
        }
        result = self.scorer.score(partial_dict)
        self.assertEqual(result["status"], ScoringStatus.SUCCESS.value)
        self.assertIn("freshness", result["unavailable_dimensions"])
        self.assertIsNone(result["dimension_scores"]["freshness"])
        # Available weight = 0.25 + 0.10 = 0.35
        expected = round((0.80 * 0.25 + 0.90 * 0.10) / 0.35, 4)
        self.assertAlmostEqual(result["overall_trust_score"], expected, places=4)

    # 15. Unknown dimension name rejection
    def test_unknown_dimension_name_rejection(self):
        """Verify that unrecognized dimension names are flagged as validation errors."""
        bad_keys = dict(self.full_scores)
        bad_keys["unrecognized_metric"] = 0.8
        result = self.scorer.score(bad_keys)
        self.assertEqual(result["status"], ScoringStatus.VALIDATION_ERROR.value)
        self.assertTrue(any("Unrecognized dimension" in err for err in result["validation_errors"]))

    # 16. Empty input dictionary
    def test_empty_input_dictionary(self):
        """Verify passing an empty dictionary {} cleanly produces INSUFFICIENT_DATA."""
        result = self.scorer.score({})
        self.assertEqual(result["status"], ScoringStatus.INSUFFICIENT_DATA.value)
        self.assertIsNone(result["overall_trust_score"])
        self.assertEqual(result["coverage_ratio"], 0.0)

    # 17. Custom valid configuration / weights
    def test_custom_valid_configuration(self):
        """Verify scorer operates accurately with custom configured weights."""
        custom_weights = {
            "source_quality": 0.40,
            "evidence_support": 0.30,
            "freshness": 0.10,
            "corroboration": 0.10,
            "consistency": 0.05,
            "data_quality": 0.05,
        }
        custom_config = TrustEngineConfig(weights=custom_weights)
        custom_scorer = TrustScorer(config=custom_config)

        # Let all scores be 0.50
        half_scores = {dim: 0.50 for dim in custom_weights.keys()}
        result = custom_scorer.score(half_scores)
        self.assertEqual(result["status"], ScoringStatus.SUCCESS.value)
        self.assertAlmostEqual(result["overall_trust_score"], 0.50, places=4)
        self.assertEqual(result["dimension_breakdown"]["source_quality"]["weight"], 0.40)

    # 18. Correct dimension-level breakdown dictionary
    def test_dimension_level_breakdown_structure(self):
        """Verify detailed per-dimension breakdown contains all required diagnostic fields."""
        scores = dict(self.full_scores)
        scores["freshness"] = None
        result = self.scorer.score(scores)

        breakdown = result["dimension_breakdown"]
        self.assertIn("source_quality", breakdown)
        sq = breakdown["source_quality"]
        self.assertEqual(sq["weight"], 0.25)
        self.assertEqual(sq["raw_score"], 0.90)
        self.assertTrue(sq["is_available"])
        self.assertAlmostEqual(sq["weighted_contribution"], 0.225, places=3)
        self.assertIn("source_quality: score 0.90", sq["explanation"])

        fr = breakdown["freshness"]
        self.assertEqual(fr["weight"], 0.15)
        self.assertIsNone(fr["raw_score"])
        self.assertFalse(fr["is_available"])
        self.assertIsNone(fr["weighted_contribution"])
        self.assertIn("unavailable", fr["explanation"])

    # 19. Division-by-zero avoidance
    def test_division_by_zero_avoidance(self):
        """Verify helper functions gracefully handle zero weights without ZeroDivisionError."""
        zero_weights = {dim: 0.0 for dim in DEFAULT_WEIGHTS.keys()}
        cov = calculate_trust_coverage(self.full_scores, zero_weights)
        self.assertEqual(cov["coverage_ratio"], 0.0)

        score = calculate_weighted_score(self.full_scores, zero_weights)
        self.assertIsNone(score)

    # 20. Deterministic repeated execution
    def test_deterministic_repeated_execution(self):
        """Verify scoring produces identical bit-for-bit results over repeated executions without mutating input."""
        original_copy = dict(self.full_scores)
        first_result = self.scorer.score(self.full_scores)

        for _ in range(30):
            repeated = self.scorer.score(self.full_scores)
            self.assertEqual(first_result["overall_trust_score"], repeated["overall_trust_score"])
            self.assertEqual(first_result["coverage_ratio"], repeated["coverage_ratio"])
            self.assertEqual(first_result["status"], repeated["status"])

        # Confirm input dictionary was not mutated
        self.assertEqual(self.full_scores, original_copy)

    # 21. Object-Oriented score_from_checkers interface
    def test_score_from_checkers_integration(self):
        """Verify TrustScorer.score_from_checkers bridges checker outputs into dimension scores."""
        intermediate = {
            "source_checker": {"average_reliability_score": 0.85},
            "freshness_checker": {"average_freshness_score": 0.75},
            "consistency_checker": {"average_consistency_score": 0.90},
            "integrity_checker": {"integrity_status": "INTACT"},
            "evidence_support": 0.80,
            "corroboration": 0.70,
        }
        res = self.scorer.score_from_checkers(intermediate)
        self.assertEqual(res["status"], ScoringStatus.SUCCESS.value)
        self.assertIsNotNone(res["overall_trust_score"])
        self.assertEqual(res["dimension_scores"]["data_quality"], 1.0)
        self.assertEqual(res["dimension_scores"]["source_quality"], 0.85)


class TestPolicyEngine(unittest.TestCase):
    """Comprehensive tests for the Policy Engine (policy_engine.py)."""

    def setUp(self):
        """Set up standard engine and scoring results for tests."""
        self.engine = PolicyEngine()

        # Standard PASS-level scoring result (mimics calculate_trust_score output)
        self.pass_scoring = {
            "overall_trust_score": 0.82,
            "coverage_ratio": 1.0,
            "status": "SUCCESS",
            "available_dimensions": [
                "source_quality", "evidence_support", "freshness",
                "corroboration", "consistency", "data_quality",
            ],
            "unavailable_dimensions": [],
            "dimension_scores": {
                "source_quality": 0.90,
                "evidence_support": 0.85,
                "freshness": 0.80,
                "corroboration": 0.75,
                "consistency": 0.90,
                "data_quality": 0.85,
            },
            "validation_errors": [],
        }

        # Standard REVIEW-level scoring result
        self.review_scoring = {
            "overall_trust_score": 0.60,
            "coverage_ratio": 0.85,
            "status": "SUCCESS",
            "available_dimensions": [
                "source_quality", "evidence_support", "freshness",
                "corroboration", "consistency",
            ],
            "unavailable_dimensions": ["data_quality"],
            "dimension_scores": {
                "source_quality": 0.55,
                "evidence_support": 0.60,
                "freshness": 0.65,
                "corroboration": 0.50,
                "consistency": 0.70,
                "data_quality": None,
            },
            "validation_errors": [],
        }

        # Standard REJECT-level scoring result
        self.reject_scoring = {
            "overall_trust_score": 0.30,
            "coverage_ratio": 0.60,
            "status": "SUCCESS",
            "available_dimensions": ["source_quality", "evidence_support", "freshness"],
            "unavailable_dimensions": ["corroboration", "consistency", "data_quality"],
            "dimension_scores": {
                "source_quality": 0.30,
                "evidence_support": 0.25,
                "freshness": 0.35,
                "corroboration": None,
                "consistency": None,
                "data_quality": None,
            },
            "validation_errors": [],
        }

    # 1. PASS threshold
    def test_pass_threshold(self):
        """Verify scores >= 0.75 with full coverage and no flags produce PASS."""
        result = self.engine.evaluate(self.pass_scoring)
        self.assertEqual(result["policy_decision"], PolicyDecision.PASS.value)
        self.assertEqual(result["status"], PolicyStatus.SUCCESS.value)
        self.assertEqual(len(result["triggered_flags"]), 0)

    # 2. REVIEW threshold
    def test_review_threshold(self):
        """Verify scores in [0.45, 0.75) produce REVIEW."""
        result = self.engine.evaluate(self.review_scoring)
        self.assertEqual(result["policy_decision"], PolicyDecision.REVIEW.value)

    # 3. REJECT threshold
    def test_reject_threshold(self):
        """Verify scores < 0.45 produce REJECT."""
        result = self.engine.evaluate(self.reject_scoring)
        self.assertEqual(result["policy_decision"], PolicyDecision.REJECT.value)

    # 4. Exact boundary values 0.45 and 0.75
    def test_exact_boundary_045(self):
        """Verify exact boundary 0.45 produces REVIEW (not REJECT)."""
        scoring = dict(self.pass_scoring)
        scoring["overall_trust_score"] = 0.45
        result = self.engine.evaluate(scoring)
        self.assertEqual(result["policy_decision"], PolicyDecision.REVIEW.value)
        self.assertEqual(result["trust_grade"], TrustGrade.MEDIUM.value)

    def test_exact_boundary_075(self):
        """Verify exact boundary 0.75 produces PASS with full coverage and no flags."""
        scoring = dict(self.pass_scoring)
        scoring["overall_trust_score"] = 0.75
        result = self.engine.evaluate(scoring)
        self.assertEqual(result["policy_decision"], PolicyDecision.PASS.value)
        self.assertEqual(result["trust_grade"], TrustGrade.HIGH.value)

    # 5. High score with INTEGRITY_MISMATCH
    def test_high_score_with_integrity_mismatch(self):
        """Verify high score with INTEGRITY_MISMATCH flag is downgraded to REVIEW."""
        result = self.engine.evaluate(
            self.pass_scoring,
            flags=[CriticalFlag.INTEGRITY_MISMATCH.value],
        )
        self.assertEqual(result["policy_decision"], PolicyDecision.REVIEW.value)
        self.assertEqual(result["trust_grade"], TrustGrade.HIGH.value)
        self.assertIn(CriticalFlag.INTEGRITY_MISMATCH.value, result["triggered_flags"])

    # 6. High score with CONTRADICTED_CLAIM
    def test_high_score_with_contradicted_claim(self):
        """Verify high score with CONTRADICTED_CLAIM flag is downgraded to REVIEW."""
        result = self.engine.evaluate(
            self.pass_scoring,
            flags=[CriticalFlag.CONTRADICTED_CLAIM.value],
        )
        self.assertEqual(result["policy_decision"], PolicyDecision.REVIEW.value)
        self.assertEqual(result["trust_grade"], TrustGrade.HIGH.value)
        self.assertIn(CriticalFlag.CONTRADICTED_CLAIM.value, result["triggered_flags"])

    # 7. High score with INCONSISTENT_DATA
    def test_high_score_with_inconsistent_data(self):
        """Verify high score with INCONSISTENT_DATA flag is downgraded to REVIEW."""
        result = self.engine.evaluate(
            self.pass_scoring,
            flags=[CriticalFlag.INCONSISTENT_DATA.value],
        )
        self.assertEqual(result["policy_decision"], PolicyDecision.REVIEW.value)
        self.assertIn(CriticalFlag.INCONSISTENT_DATA.value, result["triggered_flags"])

    # 8. High score with FUTURE_DATED_EVIDENCE
    def test_high_score_with_future_dated_evidence(self):
        """Verify high score with FUTURE_DATED_EVIDENCE flag is downgraded to REVIEW."""
        result = self.engine.evaluate(
            self.pass_scoring,
            flags=[CriticalFlag.FUTURE_DATED_EVIDENCE.value],
        )
        self.assertEqual(result["policy_decision"], PolicyDecision.REVIEW.value)
        self.assertIn(CriticalFlag.FUTURE_DATED_EVIDENCE.value, result["triggered_flags"])

    # 9. Low coverage preventing PASS
    def test_low_coverage_prevents_pass(self):
        """Verify coverage below 0.50 prevents PASS even with a high trust score."""
        scoring = dict(self.pass_scoring)
        scoring["coverage_ratio"] = 0.40
        result = self.engine.evaluate(scoring)
        self.assertEqual(result["policy_decision"], PolicyDecision.REVIEW.value)
        self.assertIn(CriticalFlag.LOW_COVERAGE.value, result["triggered_flags"])

    # 10. Score is None
    def test_score_is_none(self):
        """Verify None score produces REVIEW with INSUFFICIENT_DATA status."""
        scoring = dict(self.pass_scoring)
        scoring["overall_trust_score"] = None
        result = self.engine.evaluate(scoring)
        self.assertEqual(result["policy_decision"], PolicyDecision.REVIEW.value)
        self.assertEqual(result["status"], PolicyStatus.INSUFFICIENT_DATA.value)
        self.assertIsNone(result["overall_trust_score"])
        self.assertEqual(result["trust_grade"], TrustGrade.UNAVAILABLE.value)

    # 11. INSUFFICIENT_DATA status from scoring
    def test_insufficient_data_status(self):
        """Verify scoring result with INSUFFICIENT_DATA status and None score produces REVIEW."""
        scoring = {
            "overall_trust_score": None,
            "coverage_ratio": 0.0,
            "status": "INSUFFICIENT_DATA",
            "unavailable_dimensions": list(DEFAULT_WEIGHTS.keys()),
            "dimension_scores": {dim: None for dim in DEFAULT_WEIGHTS.keys()},
            "validation_errors": [],
        }
        result = self.engine.evaluate(scoring)
        self.assertEqual(result["policy_decision"], PolicyDecision.REVIEW.value)
        self.assertEqual(result["status"], PolicyStatus.INSUFFICIENT_DATA.value)
        self.assertIsNone(result["overall_trust_score"])

    # 12. Invalid score (out of bounds)
    def test_invalid_score_out_of_bounds(self):
        """Verify out-of-bounds scores are handled safely without producing PASS."""
        scoring = dict(self.pass_scoring)
        scoring["overall_trust_score"] = 1.5
        result = self.engine.evaluate(scoring)
        self.assertNotEqual(result["policy_decision"], PolicyDecision.PASS.value)

        scoring2 = dict(self.pass_scoring)
        scoring2["overall_trust_score"] = -0.3
        result2 = self.engine.evaluate(scoring2)
        self.assertNotEqual(result2["policy_decision"], PolicyDecision.PASS.value)

    # 13. Invalid coverage
    def test_invalid_coverage(self):
        """Verify invalid coverage values prevent PASS."""
        scoring = dict(self.pass_scoring)
        scoring["coverage_ratio"] = "invalid"
        result = self.engine.evaluate(scoring)
        self.assertNotEqual(result["policy_decision"], PolicyDecision.PASS.value)

    # 14. Missing dimensions
    def test_missing_dimensions_in_warnings(self):
        """Verify unavailable dimensions are listed in warnings."""
        result = self.engine.evaluate(self.review_scoring)
        warning_text = " ".join(result["warnings"])
        self.assertIn("data_quality", warning_text)

    # 15. Multiple simultaneous flags
    def test_multiple_simultaneous_flags(self):
        """Verify multiple critical flags all appear in triggered_flags."""
        flags = [
            CriticalFlag.INTEGRITY_MISMATCH.value,
            CriticalFlag.CONTRADICTED_CLAIM.value,
            CriticalFlag.INCONSISTENT_DATA.value,
        ]
        result = self.engine.evaluate(self.pass_scoring, flags=flags)
        self.assertEqual(result["policy_decision"], PolicyDecision.REVIEW.value)
        for flag in flags:
            self.assertIn(flag, result["triggered_flags"])
        self.assertTrue(len(result["triggered_flags"]) >= 3)

    # 16. Trust grade calculation
    def test_trust_grade_calculation(self):
        """Verify calculate_trust_grade returns correct grades for different score levels."""
        self.assertEqual(calculate_trust_grade(0.90), TrustGrade.HIGH.value)
        self.assertEqual(calculate_trust_grade(0.75), TrustGrade.HIGH.value)
        self.assertEqual(calculate_trust_grade(0.60), TrustGrade.MEDIUM.value)
        self.assertEqual(calculate_trust_grade(0.45), TrustGrade.MEDIUM.value)
        self.assertEqual(calculate_trust_grade(0.30), TrustGrade.LOW.value)
        self.assertEqual(calculate_trust_grade(0.0), TrustGrade.LOW.value)
        self.assertEqual(calculate_trust_grade(None), TrustGrade.UNAVAILABLE.value)

    # 17. Grade and policy decision remaining separate
    def test_grade_and_decision_separation(self):
        """Verify trust grade reflects score, while policy decision enforces safety flags."""
        # Score 0.90 -> HIGH grade, but INTEGRITY_MISMATCH -> REVIEW decision
        scoring = dict(self.pass_scoring)
        scoring["overall_trust_score"] = 0.90
        result = self.engine.evaluate(
            scoring,
            flags=[CriticalFlag.INTEGRITY_MISMATCH.value],
        )
        self.assertEqual(result["trust_grade"], TrustGrade.HIGH.value)
        self.assertEqual(result["policy_decision"], PolicyDecision.REVIEW.value)

        # Score 0.80 -> HIGH grade, low coverage -> REVIEW decision
        scoring2 = dict(self.pass_scoring)
        scoring2["overall_trust_score"] = 0.80
        scoring2["coverage_ratio"] = 0.35
        result2 = self.engine.evaluate(scoring2)
        self.assertEqual(result2["trust_grade"], TrustGrade.HIGH.value)
        self.assertEqual(result2["policy_decision"], PolicyDecision.REVIEW.value)

    # 18. Dictionary input directly from scoring.py
    def test_dictionary_input_from_scoring(self):
        """Verify Policy Engine accepts the exact output format from calculate_trust_score."""
        scores = {
            "source_quality": 0.90,
            "evidence_support": 0.80,
            "freshness": 0.70,
            "corroboration": 0.85,
            "consistency": 0.95,
            "data_quality": 1.00,
        }
        scoring_result = calculate_trust_score(scores)
        result = self.engine.evaluate(scoring_result)

        self.assertIn(result["policy_decision"], [d.value for d in PolicyDecision])
        self.assertIn(result["trust_grade"], [g.value for g in TrustGrade])
        self.assertIsInstance(result["triggered_flags"], list)
        self.assertIsInstance(result["reasons"], list)
        self.assertIsInstance(result["warnings"], list)
        self.assertIsInstance(result["explanation"], str)
        self.assertIn(result["status"], [s.value for s in PolicyStatus])

    # 19. Empty input
    def test_empty_input(self):
        """Verify empty dict and None both produce REVIEW with INSUFFICIENT_DATA."""
        result_empty = self.engine.evaluate({})
        self.assertEqual(result_empty["policy_decision"], PolicyDecision.REVIEW.value)
        self.assertEqual(result_empty["status"], PolicyStatus.INSUFFICIENT_DATA.value)

        result_none = self.engine.evaluate(None)
        self.assertEqual(result_none["policy_decision"], PolicyDecision.REVIEW.value)
        self.assertEqual(result_none["status"], PolicyStatus.INSUFFICIENT_DATA.value)

    # 20. Deterministic results
    def test_deterministic_results(self):
        """Verify repeated evaluations produce identical results."""
        first = self.engine.evaluate(self.pass_scoring)
        for _ in range(30):
            repeated = self.engine.evaluate(self.pass_scoring)
            self.assertEqual(first["policy_decision"], repeated["policy_decision"])
            self.assertEqual(first["trust_grade"], repeated["trust_grade"])
            self.assertEqual(first["coverage_ratio"], repeated["coverage_ratio"])
            self.assertEqual(first["triggered_flags"], repeated["triggered_flags"])
            self.assertEqual(first["explanation"], repeated["explanation"])
            self.assertEqual(first["status"], repeated["status"])

    # 21. Report structure completeness
    def test_report_structure_completeness(self):
        """Verify every expected key is present in the policy report."""
        result = self.engine.evaluate(self.pass_scoring)
        expected_keys = {
            "overall_trust_score", "trust_grade", "policy_decision",
            "coverage_ratio", "triggered_flags", "reasons",
            "warnings", "explanation", "status",
        }
        self.assertTrue(expected_keys.issubset(set(result.keys())))

    # 22. determine_policy_decision function
    def test_determine_policy_decision_function(self):
        """Verify the standalone determine_policy_decision function works correctly."""
        res_pass = determine_policy_decision(0.80)
        self.assertEqual(res_pass.decision, PolicyDecision.PASS.value)

        res_review = determine_policy_decision(0.60)
        self.assertEqual(res_review.decision, PolicyDecision.REVIEW.value)

        res_reject = determine_policy_decision(0.30)
        self.assertEqual(res_reject.decision, PolicyDecision.REJECT.value)

        res_none = determine_policy_decision(None)
        self.assertEqual(res_none.decision, PolicyDecision.REVIEW.value)

    # 23. Flags do not force REJECT automatically
    def test_flags_do_not_force_reject(self):
        """Verify critical flags force at most REVIEW, never automatically REJECT."""
        all_flags = [f.value for f in CriticalFlag]
        result = self.engine.evaluate(self.pass_scoring, flags=all_flags)
        # REVIEW at minimum, but not automatically REJECT for a high scoring result
        self.assertEqual(result["policy_decision"], PolicyDecision.REVIEW.value)

    # 24. Coverage exactly at 0.50 boundary
    def test_coverage_exactly_050(self):
        """Verify coverage at exactly 0.50 does not prevent PASS (boundary is < 0.50)."""
        scoring = dict(self.pass_scoring)
        scoring["coverage_ratio"] = 0.50
        result = self.engine.evaluate(scoring)
        # Score 0.82 and coverage 0.50 (not below threshold) -> PASS
        self.assertEqual(result["policy_decision"], PolicyDecision.PASS.value)


class TestTrustEngineCoordinator(unittest.TestCase):
    """End-to-end integration tests for the Main Trust Engine Coordinator."""

    def setUp(self):
        """Set up standard test fixtures matching Member 1's integration contract."""
        self.coordinator = TrustEngineCoordinator()

        # Member 1's standard verified sample packet
        self.sample_packet = {
            "task_id": "task_001",
            "status": "success",
            "agent": "orchestrator",
            "data": {
                "claims": [
                    {
                        "claim_id": "C1",
                        "claim_text": "Solar power generation increased in 2024.",
                        "evidence_ids": ["E1", "E2"],
                    }
                ],
                "evidence": [
                    {
                        "evidence_id": "E1",
                        "source_url": "https://energy.gov/solar-report",
                        "source_title": "Department of Energy Solar Report",
                        "snippet": "Solar capacity grew by 24% nationwide.",
                        "source_type": "government",
                        "publication_date": "2024-06-01T00:00:00Z",
                    },
                    {
                        "evidence_id": "E2",
                        "source_url": "https://reuters.com/business/energy/solar-2024",
                        "source_title": "Reuters Energy Market Update",
                        "snippet": "Renewable energy markets report record expansion.",
                        "source_type": "news",
                        "publication_date": "2024-06-15T00:00:00Z",
                    },
                ],
                "verification_results": [
                    {
                        "claim_id": "C1",
                        "status": "SUPPORTED",
                        "supporting_evidence_ids": ["E1", "E2"],
                        "contradicting_evidence_ids": [],
                        "explanation": "Supported by Department of Energy and Reuters reports.",
                    }
                ],
            },
            "error": None,
        }

    # 1. Complete valid verification packet
    def test_complete_valid_verification_packet(self):
        """Verify that a full valid packet produces a complete PASS response."""
        res = evaluate_trust_engine(self.sample_packet)
        self.assertEqual(res["status"], "success")
        self.assertEqual(res["agent"], "trust_engine")
        self.assertEqual(res["task_id"], "task_001")
        self.assertIsNone(res["error"])

        data = res["data"]
        self.assertIsNotNone(data["overall_trust_score"])
        self.assertGreaterEqual(data["overall_trust_score"], 0.75)
        self.assertEqual(data["policy_decision"], PolicyDecision.PASS.value)
        self.assertEqual(data["trust_grade"], TrustGrade.HIGH.value)
        self.assertEqual(len(data["claim_evaluations"]), 1)

    # 2. Multiple claims
    def test_multiple_claims(self):
        """Verify packet containing multiple claims evaluates all claims individually."""
        packet = {
            "task_id": "task_multi",
            "status": "success",
            "agent": "orchestrator",
            "data": {
                "claims": [
                    {"claim_id": "C1", "claim_text": "Claim 1", "evidence_ids": ["E1"]},
                    {"claim_id": "C2", "claim_text": "Claim 2", "evidence_ids": ["E2"]},
                    {"claim_id": "C3", "claim_text": "Claim 3", "evidence_ids": ["E1", "E2"]},
                ],
                "evidence": [
                    {"evidence_id": "E1", "source_url": "https://science.org/1", "source_title": "Science", "snippet": "Text 1", "source_type": "academic"},
                    {"evidence_id": "E2", "source_url": "https://bbc.com/2", "source_title": "BBC", "snippet": "Text 2", "source_type": "news"},
                ],
                "verification_results": [
                    {"claim_id": "C1", "status": "SUPPORTED", "supporting_evidence_ids": ["E1"], "contradicting_evidence_ids": []},
                    {"claim_id": "C2", "status": "SUPPORTED", "supporting_evidence_ids": ["E2"], "contradicting_evidence_ids": []},
                    {"claim_id": "C3", "status": "SUPPORTED", "supporting_evidence_ids": ["E1", "E2"], "contradicting_evidence_ids": []},
                ],
            },
            "error": None,
        }
        res = evaluate_trust_engine(packet)
        self.assertEqual(len(res["data"]["claim_evaluations"]), 3)
        claim_ids = [c["claim_id"] for c in res["data"]["claim_evaluations"]]
        self.assertListEqual(claim_ids, ["C1", "C2", "C3"])

    # 3. Multiple evidence items
    def test_multiple_evidence_items(self):
        """Verify handling of multiple diverse evidence items."""
        packet = dict(self.sample_packet)
        res = evaluate_trust_engine(packet)
        self.assertIn("source_quality", res["data"]["available_dimensions"])
        self.assertGreater(res["data"]["dimension_scores"]["source_quality"], 0.70)

    # 4. Supported claim
    def test_supported_claim(self):
        """Verify a supported claim produces positive support score without contradiction flags."""
        res = evaluate_trust_engine(self.sample_packet)
        clm_eval = res["data"]["claim_evaluations"][0]
        self.assertEqual(clm_eval["verification_status"], "SUPPORTED")
        self.assertEqual(clm_eval["evidence_support_score"], 1.0)
        self.assertNotIn(CriticalFlag.CONTRADICTED_CLAIM.value, res["data"]["triggered_flags"])

    # 5. Contradicted claim
    def test_contradicted_claim(self):
        """Verify a contradicted claim triggers CONTRADICTED_CLAIM flag and forces at least REVIEW."""
        packet = {
            "task_id": "task_contra",
            "status": "success",
            "agent": "orchestrator",
            "data": {
                "claims": [{"claim_id": "C1", "claim_text": "Unverified claim", "evidence_ids": ["E1"]}],
                "evidence": [{"evidence_id": "E1", "source_url": "https://reuters.com/1", "source_title": "R", "snippet": "Refutation", "source_type": "news"}],
                "verification_results": [
                    {
                        "claim_id": "C1",
                        "status": "CONTRADICTED",
                        "supporting_evidence_ids": [],
                        "contradicting_evidence_ids": ["E1"],
                        "explanation": "Contradicted by news source.",
                    }
                ],
            },
            "error": None,
        }
        res = evaluate_trust_engine(packet)
        self.assertIn(CriticalFlag.CONTRADICTED_CLAIM.value, res["data"]["triggered_flags"])
        self.assertEqual(res["data"]["policy_decision"], PolicyDecision.REVIEW.value)

    # 6. Insufficient verification result
    def test_insufficient_verification_result(self):
        """Verify an INSUFFICIENT verification status is treated conservatively (support score 0.0)."""
        packet = {
            "task_id": "task_insuff",
            "status": "success",
            "agent": "orchestrator",
            "data": {
                "claims": [{"claim_id": "C1", "claim_text": "Uncertain claim", "evidence_ids": ["E1"]}],
                "evidence": [{"evidence_id": "E1", "source_url": "https://example.com/1", "source_title": "Ex", "snippet": "Vague", "source_type": "website"}],
                "verification_results": [
                    {
                        "claim_id": "C1",
                        "status": "INSUFFICIENT",
                        "supporting_evidence_ids": [],
                        "contradicting_evidence_ids": [],
                        "explanation": "Evidence is inconclusive.",
                    }
                ],
            },
            "error": None,
        }
        res = evaluate_trust_engine(packet)
        clm_eval = res["data"]["claim_evaluations"][0]
        self.assertEqual(clm_eval["verification_status"], "INSUFFICIENT")
        self.assertEqual(clm_eval["evidence_support_score"], 0.0)

    # 7. Missing publication date
    def test_missing_publication_date(self):
        """Verify evidence lacking publication_date leaves freshness dimension as None without failing."""
        packet = {
            "task_id": "task_no_date",
            "status": "success",
            "agent": "orchestrator",
            "data": {
                "claims": [{"claim_id": "C1", "claim_text": "Dated claim", "evidence_ids": ["E1"]}],
                "evidence": [
                    {
                        "evidence_id": "E1",
                        "source_url": "https://gov.us/doc",
                        "source_title": "Gov Doc",
                        "snippet": "Content",
                        "source_type": "government",
                        # No publication_date provided
                    }
                ],
                "verification_results": [
                    {"claim_id": "C1", "status": "SUPPORTED", "supporting_evidence_ids": ["E1"], "contradicting_evidence_ids": []}
                ],
            },
            "error": None,
        }
        res = evaluate_trust_engine(packet)
        self.assertIsNone(res["data"]["dimension_scores"]["freshness"])
        self.assertIn("freshness", res["data"]["unavailable_dimensions"])

    # 8. Future-dated evidence
    def test_future_dated_evidence(self):
        """Verify that future publication dates trigger FUTURE_DATED_EVIDENCE flag and force REVIEW."""
        packet = {
            "task_id": "task_future",
            "status": "success",
            "agent": "orchestrator",
            "data": {
                "claims": [{"claim_id": "C1", "claim_text": "Claim", "evidence_ids": ["E1"]}],
                "evidence": [
                    {
                        "evidence_id": "E1",
                        "source_url": "https://nature.com/f",
                        "source_title": "Paper",
                        "snippet": "Text",
                        "source_type": "academic",
                        "publication_date": "2099-12-31T00:00:00Z",  # Far in the future
                    }
                ],
                "verification_results": [
                    {"claim_id": "C1", "status": "SUPPORTED", "supporting_evidence_ids": ["E1"], "contradicting_evidence_ids": []}
                ],
            },
            "error": None,
        }
        res = evaluate_trust_engine(packet)
        self.assertIn(CriticalFlag.FUTURE_DATED_EVIDENCE.value, res["data"]["triggered_flags"])
        self.assertEqual(res["data"]["policy_decision"], PolicyDecision.REVIEW.value)

    # 9. Missing structured consistency data
    def test_missing_structured_consistency_data(self):
        """Verify that when no structured metrics are supplied, consistency dimension remains None."""
        res = evaluate_trust_engine(self.sample_packet)
        self.assertIsNone(res["data"]["dimension_scores"]["consistency"])
        self.assertIn("consistency", res["data"]["unavailable_dimensions"])

    # 10. Actual structured numerical conflict
    def test_actual_structured_numerical_conflict(self):
        """Verify that genuine conflicting structured metrics trigger INCONSISTENT_DATA flag."""
        packet = {
            "task_id": "task_conflict",
            "status": "success",
            "agent": "orchestrator",
            "data": {
                "claims": [
                    {
                        "claim_id": "C1",
                        "claim_text": "Speed of vehicle",
                        "evidence_ids": ["E1", "E2"],
                        "metadata": {
                            "structured_data": [
                                {"evidence_id": "E1", "metric": "speed", "value": 50, "unit": "km/h"},
                                {"evidence_id": "E2", "metric": "speed", "value": 150, "unit": "km/h"},
                            ]
                        },
                    }
                ],
                "evidence": [
                    {"evidence_id": "E1", "source_url": "https://reuters.com/1", "source_title": "R1", "snippet": "50 km/h", "source_type": "news"},
                    {"evidence_id": "E2", "source_url": "https://reuters.com/2", "source_title": "R2", "snippet": "150 km/h", "source_type": "news"},
                ],
                "verification_results": [
                    {"claim_id": "C1", "status": "SUPPORTED", "supporting_evidence_ids": ["E1"], "contradicting_evidence_ids": []}
                ],
            },
            "error": None,
        }
        res = evaluate_trust_engine(packet)
        self.assertIn(CriticalFlag.INCONSISTENT_DATA.value, res["data"]["triggered_flags"])
        self.assertEqual(res["data"]["policy_decision"], PolicyDecision.REVIEW.value)

    # 11. Missing local file for integrity checking
    def test_missing_local_file_for_integrity(self):
        """Verify evidence with baseline hash but missing local file path does not trigger false mismatch."""
        packet = {
            "task_id": "task_no_file",
            "status": "success",
            "agent": "orchestrator",
            "data": {
                "claims": [{"claim_id": "C1", "claim_text": "File claim", "evidence_ids": ["E1"]}],
                "evidence": [
                    {
                        "evidence_id": "E1",
                        "source_url": "https://example.com/doc",
                        "source_title": "Doc",
                        "snippet": "Text",
                        "source_type": "website",
                        "sha256_hash": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                        # No local file_path provided in metadata
                    }
                ],
                "verification_results": [
                    {"claim_id": "C1", "status": "SUPPORTED", "supporting_evidence_ids": ["E1"], "contradicting_evidence_ids": []}
                ],
            },
            "error": None,
        }
        res = evaluate_trust_engine(packet)
        # Should not falsely trigger integrity mismatch
        self.assertNotIn(CriticalFlag.INTEGRITY_MISMATCH.value, res["data"]["triggered_flags"])

    # 12. Actual integrity mismatch when a trusted baseline and local file are supplied
    def test_actual_integrity_mismatch(self):
        """Verify that when a local file's hash differs from baseline, INTEGRITY_MISMATCH is triggered."""
        with tempfile.NamedTemporaryFile(mode="w", delete=False) as f:
            f.write("actual local content on disk")
            temp_path = f.name

        try:
            fake_baseline = "a" * 64
            packet = {
                "task_id": "task_mismatch",
                "status": "success",
                "agent": "orchestrator",
                "data": {
                    "claims": [{"claim_id": "C1", "claim_text": "File content", "evidence_ids": ["E1"]}],
                    "evidence": [
                        {
                            "evidence_id": "E1",
                            "source_url": "https://example.com/file",
                            "source_title": "File",
                            "snippet": "Content",
                            "source_type": "website",
                            "sha256_hash": fake_baseline,
                            "metadata": {"local_path": temp_path},
                        }
                    ],
                    "verification_results": [
                        {"claim_id": "C1", "status": "SUPPORTED", "supporting_evidence_ids": ["E1"], "contradicting_evidence_ids": []}
                    ],
                },
                "error": None,
            }
            res = evaluate_trust_engine(packet)
            self.assertIn(CriticalFlag.INTEGRITY_MISMATCH.value, res["data"]["triggered_flags"])
            self.assertEqual(res["data"]["policy_decision"], PolicyDecision.REVIEW.value)
        finally:
            if os.path.exists(temp_path):
                os.remove(temp_path)

    # 13. Missing optional metadata
    def test_missing_optional_metadata(self):
        """Verify packet with bare minimum evidence fields evaluates without crashing."""
        packet = {
            "task_id": "task_bare",
            "status": "success",
            "agent": "orchestrator",
            "data": {
                "claims": [{"claim_id": "C1", "claim_text": "Bare claim", "evidence_ids": ["E1"]}],
                "evidence": [
                    {
                        "evidence_id": "E1",
                        # Omit source_url, source_title, snippet, publication_date, sha256_hash
                    }
                ],
                "verification_results": [
                    {"claim_id": "C1", "status": "SUPPORTED", "supporting_evidence_ids": ["E1"], "contradicting_evidence_ids": []}
                ],
            },
            "error": None,
        }
        res = evaluate_trust_engine(packet)
        self.assertEqual(res["status"], "success")
        self.assertIsNotNone(res["data"]["policy_decision"])

    # 14. Empty claims
    def test_empty_claims(self):
        """Verify packet with empty claims list returns safe response."""
        packet = {
            "task_id": "task_empty_claims",
            "status": "success",
            "agent": "orchestrator",
            "data": {
                "claims": [],
                "evidence": [
                    {"evidence_id": "E1", "source_url": "https://gov.us", "source_title": "G", "snippet": "S", "source_type": "government"}
                ],
                "verification_results": [],
            },
            "error": None,
        }
        res = evaluate_trust_engine(packet)
        self.assertEqual(res["status"], "success")
        self.assertEqual(len(res["data"]["claim_evaluations"]), 0)

    # 15. Empty evidence
    def test_empty_evidence(self):
        """Verify packet with empty evidence list returns safe response without division by zero."""
        packet = {
            "task_id": "task_empty_evidence",
            "status": "success",
            "agent": "orchestrator",
            "data": {
                "claims": [{"claim_id": "C1", "claim_text": "Claim", "evidence_ids": []}],
                "evidence": [],
                "verification_results": [],
            },
            "error": None,
        }
        res = evaluate_trust_engine(packet)
        self.assertEqual(res["status"], "success")
        self.assertEqual(res["data"]["policy_decision"], PolicyDecision.REVIEW.value)

    # 16. Invalid packet
    def test_invalid_packet(self):
        """Verify invalid or non-dict packets return structured error response."""
        for bad_packet in [None, "string_packet", 12345]:
            res = evaluate_trust_engine(bad_packet)
            self.assertEqual(res["status"], "error")
            self.assertIsNotNone(res["error"])
            self.assertEqual(res["data"]["policy_decision"], PolicyDecision.REVIEW.value)

    # 17. Missing common envelope fields
    def test_missing_common_envelope_fields(self):
        """Verify packet missing task_id returns error envelope."""
        packet = {
            "status": "success",
            "agent": "orchestrator",
            # missing task_id
            "data": {"claims": []},
        }
        res = evaluate_trust_engine(packet)
        self.assertEqual(res["status"], "error")
        self.assertIn("task_id", res["error"])

    # 18. No available scoring dimensions
    def test_no_available_scoring_dimensions(self):
        """Verify that when no dimensions can be evaluated, status is INSUFFICIENT_DATA and decision is REVIEW."""
        packet = {
            "task_id": "task_no_dims",
            "status": "success",
            "agent": "orchestrator",
            "data": {
                "claims": [],
                "evidence": [],
                "verification_results": [],
            },
            "error": None,
        }
        res = evaluate_trust_engine(packet)
        self.assertEqual(res["status"], "success")
        self.assertIsNone(res["data"]["overall_trust_score"])
        self.assertEqual(res["data"]["trust_grade"], TrustGrade.UNAVAILABLE.value)
        self.assertEqual(res["data"]["policy_decision"], PolicyDecision.REVIEW.value)

    # 19. Correct policy integration
    def test_correct_policy_integration(self):
        """Verify policy engine thresholds and decisions are accurately reflected."""
        res_pass = evaluate_trust_engine(self.sample_packet)
        self.assertEqual(res_pass["data"]["policy_decision"], PolicyDecision.PASS.value)

    # 20. Correct output envelope structure
    def test_correct_output_envelope(self):
        """Verify final output envelope contains all required top-level and data fields."""
        res = evaluate_trust_engine(self.sample_packet)
        top_keys = {"task_id", "status", "agent", "data", "error"}
        self.assertTrue(top_keys.issubset(set(res.keys())))
        self.assertEqual(res["agent"], "trust_engine")

        data = res["data"]
        data_keys = {
            "overall_trust_score",
            "trust_grade",
            "policy_decision",
            "coverage_ratio",
            "dimension_scores",
            "dimension_breakdown",
            "available_dimensions",
            "unavailable_dimensions",
            "triggered_flags",
            "claim_evaluations",
            "trust_report",
        }
        self.assertTrue(data_keys.issubset(set(data.keys())))

        report_keys = {"summary", "explanation", "warnings", "recommendations"}
        self.assertTrue(report_keys.issubset(set(data["trust_report"].keys())))

    # 21. No fabricated trust scores
    def test_no_fabricated_trust_scores(self):
        """Verify missing dimensions remain None and are not filled with 0.0 or 1.0."""
        res = evaluate_trust_engine(self.sample_packet)
        dim_scores = res["data"]["dimension_scores"]
        # In sample_packet, consistency is missing
        self.assertIsNone(dim_scores["consistency"])

    # 22. Multiple simultaneous flags
    def test_multiple_simultaneous_flags(self):
        """Verify multiple critical flags are all captured simultaneously."""
        with tempfile.NamedTemporaryFile(mode="w", delete=False) as f:
            f.write("actual content")
            temp_path = f.name

        try:
            packet = {
                "task_id": "task_multi_flags",
                "status": "success",
                "agent": "orchestrator",
                "data": {
                    "claims": [
                        {
                            "claim_id": "C1",
                            "claim_text": "Claim",
                            "evidence_ids": ["E1"],
                            "metadata": {
                                "structured_data": [
                                    {"evidence_id": "E1", "metric": "val", "value": 10},
                                    {"evidence_id": "E1", "metric": "val", "value": 999},
                                ]
                            },
                        }
                    ],
                    "evidence": [
                        {
                            "evidence_id": "E1",
                            "source_url": "https://gov.us",
                            "source_title": "Gov",
                            "snippet": "Text",
                            "source_type": "government",
                            "publication_date": "2099-01-01T00:00:00Z",  # Future-dated
                            "sha256_hash": "b" * 64,                     # Integrity mismatch
                            "metadata": {"local_path": temp_path},
                        }
                    ],
                    "verification_results": [
                        {
                            "claim_id": "C1",
                            "status": "CONTRADICTED",                   # Contradicted claim
                            "supporting_evidence_ids": [],
                            "contradicting_evidence_ids": ["E1"],
                        }
                    ],
                },
                "error": None,
            }
            res = evaluate_trust_engine(packet)
            flags = res["data"]["triggered_flags"]
            self.assertIn(CriticalFlag.CONTRADICTED_CLAIM.value, flags)
            self.assertIn(CriticalFlag.FUTURE_DATED_EVIDENCE.value, flags)
            self.assertIn(CriticalFlag.INTEGRITY_MISMATCH.value, flags)
            self.assertIn(CriticalFlag.INCONSISTENT_DATA.value, flags)
            # Score is very low due to contradictions and inconsistencies (< 0.45), so decision is REJECT
            self.assertEqual(res["data"]["policy_decision"], PolicyDecision.REJECT.value)
        finally:
            if os.path.exists(temp_path):
                os.remove(temp_path)

    # 23. Deterministic results
    def test_deterministic_results(self):
        """Verify repeated executions produce bit-for-bit identical responses without mutating packet."""
        orig_copy = dict(self.sample_packet)
        first_res = evaluate_trust_engine(self.sample_packet)

        for _ in range(25):
            repeated = evaluate_trust_engine(self.sample_packet)
            self.assertEqual(first_res["data"]["overall_trust_score"], repeated["data"]["overall_trust_score"])
            self.assertEqual(first_res["data"]["policy_decision"], repeated["data"]["policy_decision"])
            self.assertEqual(first_res["data"]["triggered_flags"], repeated["data"]["triggered_flags"])

        # Packet was not mutated
        self.assertEqual(self.sample_packet, orig_copy)

    # 24. Member 1's original packet compatibility
    def test_member1_original_packet_compatibility(self):
        """Verify exact compatibility with Member 1's specified specification packet."""
        member1_packet = {
            "task_id": "task_001",
            "status": "success",
            "agent": "orchestrator",
            "data": {
                "claims": [
                    {
                        "claim_id": "C1",
                        "claim_text": "Example claim",
                        "evidence_ids": ["E1"],
                    }
                ],
                "evidence": [
                    {
                        "evidence_id": "E1",
                        "source_url": "https://example.com",
                        "source_title": "Example Source",
                        "snippet": "Example evidence",
                        "source_type": "website",
                    }
                ],
                "verification_results": [
                    {
                        "claim_id": "C1",
                        "status": "SUPPORTED",
                        "supporting_evidence_ids": ["E1"],
                        "contradicting_evidence_ids": [],
                        "explanation": "Example explanation",
                    }
                ],
            },
            "error": None,
        }
        res = evaluate_trust_engine(member1_packet)
        self.assertEqual(res["task_id"], "task_001")
        self.assertEqual(res["status"], "success")
        self.assertEqual(res["agent"], "trust_engine")
        self.assertIsNotNone(res["data"]["overall_trust_score"])
        self.assertIn(res["data"]["policy_decision"], [PolicyDecision.PASS.value, PolicyDecision.REVIEW.value, PolicyDecision.REJECT.value])
        self.assertEqual(len(res["data"]["claim_evaluations"]), 1)


if __name__ == "__main__":
    unittest.main()
