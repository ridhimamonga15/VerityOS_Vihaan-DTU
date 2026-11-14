"""Cryptographic Integrity Checker Component for VerityOS.

This module provides SHA-256 based cryptographic file integrity verification.
It detects whether file contents have changed compared to a previously trusted baseline hash.

Core Principles:
1. Uses Python's standard `hashlib` and `hmac` libraries exclusively.
2. Large files are handled via chunk-based streaming to ensure minimal memory footprint.
3. Constant-time string comparison (`hmac.compare_digest`) prevents timing attacks.
4. Baseline hashes are treated as immutable trusted baselines and are NEVER overwritten.
5. A SHA-256 mismatch indicates changed file contents, not necessarily malicious activity.
6. The presence of a hash does NOT automatically imply that the file is safe or authentic.
"""

from enum import Enum
import hashlib
import hmac
import os
from pathlib import Path
import re
from typing import Any, Dict, Optional, Union


# ---------------------------------------------------------------------------
# Constants and Enums
# ---------------------------------------------------------------------------

DEFAULT_CHUNK_SIZE: int = 65536  # 64 KB chunks for memory-efficient streaming
SHA256_HEX_LENGTH: int = 64
_SHA256_PATTERN = re.compile(r"^[0-9a-fA-F]{64}$")


class IntegrityStatus(str, Enum):
    """Integrity evaluation statuses for files and evidence payloads."""
    INTACT = "INTACT"       # File matches the trusted baseline hash
    MODIFIED = "MODIFIED"   # File contents differ from the baseline hash
    MISSING = "MISSING"     # File path does not exist on disk
    ERROR = "ERROR"         # Validation failed, malformed hash, or unreadable path


# ---------------------------------------------------------------------------
# Hash Validation Helpers
# ---------------------------------------------------------------------------

def is_valid_sha256(hash_str: Optional[str]) -> bool:
    """Validate whether a string is a well-formed 64-character SHA-256 hex string.
    
    Args:
        hash_str: The string to test.
        
    Returns:
        True if the string contains exactly 64 hexadecimal characters, False otherwise.
    """
    if not isinstance(hash_str, str):
        return False
    return bool(_SHA256_PATTERN.fullmatch(hash_str.strip()))


# ---------------------------------------------------------------------------
# Core Functional API
# ---------------------------------------------------------------------------

def calculate_file_hash(
    file_path: Union[str, Path],
    chunk_size: int = DEFAULT_CHUNK_SIZE
) -> str:
    """Calculate the SHA-256 hexadecimal digest of a local file.
    
    Reads the file safely in binary mode using fixed-size chunks to support
    very large files without high memory consumption.
    
    Args:
        file_path: Path to the target file.
        chunk_size: Size of data chunks to read into memory per iteration.
        
    Returns:
        Hexadecimal SHA-256 hash string (lowercase).
        
    Raises:
        FileNotFoundError: If the specified file does not exist.
        IsADirectoryError: If the path points to a directory instead of a file.
        PermissionError: If read permissions are denied.
        ValueError: If file_path is empty or chunk_size is invalid.
    """
    if not file_path or not str(file_path).strip():
        raise ValueError("File path cannot be empty or whitespace.")

    if chunk_size <= 0:
        raise ValueError(f"chunk_size must be a positive integer, got {chunk_size}.")

    path_obj = Path(file_path)

    if not path_obj.exists():
        raise FileNotFoundError(f"File not found: '{file_path}'")

    if path_obj.is_dir():
        raise IsADirectoryError(f"Path is a directory, not a file: '{file_path}'")

    hasher = hashlib.sha256()

    with open(path_obj, "rb") as f:
        while True:
            chunk = f.read(chunk_size)
            if not chunk:
                break
            hasher.update(chunk)

    return hasher.hexdigest().lower()


def compare_hashes(expected_hash: Optional[str], actual_hash: Optional[str]) -> bool:
    """Compare two SHA-256 hashes safely using constant-time comparison.
    
    Uses `hmac.compare_digest` to mitigate side-channel timing attacks and
    normalizes hexadecimal strings to lowercase for case-insensitive matching.
    
    Args:
        expected_hash: The trusted baseline hash.
        actual_hash: The calculated current hash.
        
    Returns:
        True if both hashes are valid 64-character SHA-256 strings and match,
        False otherwise.
    """
    if not is_valid_sha256(expected_hash) or not is_valid_sha256(actual_hash):
        return False

    norm_expected = expected_hash.strip().lower()
    norm_actual = actual_hash.strip().lower()

    return hmac.compare_digest(norm_expected, norm_actual)


def verify_file_integrity(
    file_path: Union[str, Path],
    expected_hash: str,
    chunk_size: int = DEFAULT_CHUNK_SIZE
) -> bool:
    """Verify whether a file's contents match the trusted baseline hash.
    
    Safe wrapper around calculate_file_hash and compare_hashes. Handles
    missing files, invalid paths, and malformed baseline hashes without crashing.
    
    Args:
        file_path: Path to the target file on disk.
        expected_hash: The trusted baseline SHA-256 hash.
        chunk_size: Chunk size for reading large files.
        
    Returns:
        True if the file exists and its hash exactly matches expected_hash;
        False if contents differ, file is missing, or hash is malformed.
    """
    if not is_valid_sha256(expected_hash):
        return False

    try:
        actual_hash = calculate_file_hash(file_path, chunk_size=chunk_size)
    except (FileNotFoundError, IsADirectoryError, PermissionError, OSError, ValueError):
        return False

    return compare_hashes(expected_hash, actual_hash)


def generate_integrity_report(
    file_path: Union[str, Path],
    expected_hash: Optional[str],
    chunk_size: int = DEFAULT_CHUNK_SIZE
) -> Dict[str, Any]:
    """Generate a structured diagnostic report on file integrity.
    
    Produces a detailed status breakdown without exposing sensitive file contents.
    
    Possible `integrity_status` outcomes:
    - INTACT:   File contents match the trusted baseline hash.
    - MODIFIED: File contents differ from the baseline hash.
    - MISSING:  File does not exist on disk.
    - ERROR:    Expected hash is invalid, path is a directory, or read access failed.
    
    Args:
        file_path: Path to the file being evaluated.
        expected_hash: The trusted baseline SHA-256 hash.
        chunk_size: Chunk size for streaming file reads.
        
    Returns:
        Dictionary containing:
        - file_path: str
        - expected_hash: Optional[str] (unmodified baseline)
        - actual_hash: Optional[str] (calculated SHA-256 or None)
        - integrity_status: str (INTACT, MODIFIED, MISSING, ERROR)
        - is_modified: bool (True if file exists but content changed)
        - explanation: str (clear, human-readable reason)
    """
    path_str = str(file_path) if file_path is not None else ""

    # 1. Validate baseline hash format
    if not is_valid_sha256(expected_hash):
        return {
            "file_path": path_str,
            "expected_hash": expected_hash,
            "actual_hash": None,
            "integrity_status": IntegrityStatus.ERROR.value,
            "is_modified": False,
            "explanation": (
                f"Invalid or malformed baseline hash: '{expected_hash}'. "
                "Expected a 64-character hexadecimal SHA-256 string."
            ),
        }

    # 2. Check path string validity
    if not path_str.strip():
        return {
            "file_path": path_str,
            "expected_hash": expected_hash,
            "actual_hash": None,
            "integrity_status": IntegrityStatus.ERROR.value,
            "is_modified": False,
            "explanation": "File path cannot be empty or whitespace.",
        }

    path_obj = Path(file_path)

    # 3. Check file existence
    if not path_obj.exists():
        return {
            "file_path": path_str,
            "expected_hash": expected_hash,
            "actual_hash": None,
            "integrity_status": IntegrityStatus.MISSING.value,
            "is_modified": False,
            "explanation": f"File does not exist at path: '{path_str}'.",
        }

    # 4. Check if path is a directory
    if path_obj.is_dir():
        return {
            "file_path": path_str,
            "expected_hash": expected_hash,
            "actual_hash": None,
            "integrity_status": IntegrityStatus.ERROR.value,
            "is_modified": False,
            "explanation": f"Specified path is a directory, not a file: '{path_str}'.",
        }

    # 5. Attempt hash calculation
    try:
        actual_hash = calculate_file_hash(path_obj, chunk_size=chunk_size)
    except PermissionError as e:
        return {
            "file_path": path_str,
            "expected_hash": expected_hash,
            "actual_hash": None,
            "integrity_status": IntegrityStatus.ERROR.value,
            "is_modified": False,
            "explanation": f"Permission denied while reading file: {e}",
        }
    except OSError as e:
        return {
            "file_path": path_str,
            "expected_hash": expected_hash,
            "actual_hash": None,
            "integrity_status": IntegrityStatus.ERROR.value,
            "is_modified": False,
            "explanation": f"I/O error while reading file: {e}",
        }

    # 6. Compare actual with baseline
    if compare_hashes(expected_hash, actual_hash):
        return {
            "file_path": path_str,
            "expected_hash": expected_hash,
            "actual_hash": actual_hash,
            "integrity_status": IntegrityStatus.INTACT.value,
            "is_modified": False,
            "explanation": "File matches the trusted baseline hash. Integrity verified.",
        }
    else:
        return {
            "file_path": path_str,
            "expected_hash": expected_hash,
            "actual_hash": actual_hash,
            "integrity_status": IntegrityStatus.MODIFIED.value,
            "is_modified": True,
            "explanation": (
                "File contents differ from the trusted baseline hash. "
                "This indicates that the content has changed since the baseline was recorded. "
                "Note: A mismatch indicates changed content, not necessarily malicious manipulation."
            ),
        }


# ---------------------------------------------------------------------------
# Object-Oriented Component Wrapper
# ---------------------------------------------------------------------------

class IntegrityChecker:
    """Verifies evidence and file data integrity using SHA-256 hashing.
    
    Maintains compatibility with `TrustEngine` coordinator initialization.
    """

    def __init__(self, chunk_size: int = DEFAULT_CHUNK_SIZE):
        """Initialize IntegrityChecker with configurable chunk size."""
        self.chunk_size = chunk_size

    def calculate_file_hash(self, file_path: Union[str, Path]) -> str:
        """Calculate SHA-256 hash of a local file."""
        return calculate_file_hash(file_path, chunk_size=self.chunk_size)

    def compare_hashes(self, expected_hash: Optional[str], actual_hash: Optional[str]) -> bool:
        """Compare two hashes using constant-time comparison."""
        return compare_hashes(expected_hash, actual_hash)

    def verify_file_integrity(self, file_path: Union[str, Path], expected_hash: str) -> bool:
        """Verify whether a local file matches the expected baseline hash."""
        return verify_file_integrity(file_path, expected_hash, chunk_size=self.chunk_size)

    def generate_report(
        self,
        file_path: Union[str, Path],
        expected_hash: Optional[str]
    ) -> Dict[str, Any]:
        """Generate a structured diagnostic integrity report."""
        return generate_integrity_report(file_path, expected_hash, chunk_size=self.chunk_size)

    def check_evidence_integrity(
        self,
        evidence_item: Any,
        file_path: Optional[Union[str, Path]] = None
    ) -> Dict[str, Any]:
        """Verify the cryptographic integrity of an Evidence item.
        
        Compatible with `schemas.Evidence` model or raw evidence dictionaries.
        
        Handles cases where:
        - No baseline hash is recorded in evidence.
        - No local file path is available (e.g. remote web sources).
        - A local file path and baseline hash are provided.
        
        Args:
            evidence_item: `Evidence` instance or dictionary.
            file_path: Optional path to the local file representing the evidence.
            
        Returns:
            Structured diagnostic dictionary.
        """
        # Extract evidence_id and sha256_hash safely
        if hasattr(evidence_item, "evidence_id"):
            evidence_id = getattr(evidence_item, "evidence_id")
            baseline_hash = getattr(evidence_item, "sha256_hash", None)
        elif isinstance(evidence_item, dict):
            evidence_id = evidence_item.get("evidence_id", "unknown_evidence")
            baseline_hash = evidence_item.get("sha256_hash", None)
        else:
            return {
                "evidence_id": "unknown",
                "integrity_status": IntegrityStatus.ERROR.value,
                "is_modified": False,
                "explanation": f"Invalid evidence item type: {type(evidence_item).__name__}.",
            }

        # Check if baseline hash is present
        if not baseline_hash:
            return {
                "evidence_id": evidence_id,
                "file_path": str(file_path) if file_path else None,
                "expected_hash": None,
                "actual_hash": None,
                "integrity_status": IntegrityStatus.MISSING.value,
                "is_modified": False,
                "explanation": (
                    "No trusted baseline SHA-256 hash was provided for this evidence item. "
                    "Cryptographic integrity verification is unavailable."
                ),
            }

        # Check if a local file path is provided
        if not file_path:
            return {
                "evidence_id": evidence_id,
                "file_path": None,
                "expected_hash": baseline_hash,
                "actual_hash": None,
                "integrity_status": IntegrityStatus.MISSING.value,
                "is_modified": False,
                "explanation": (
                    "A trusted baseline hash was provided, but no local file path was supplied. "
                    "Cannot independently hash remote or missing local content."
                ),
            }

        # Run file integrity report
        report = self.generate_report(file_path, baseline_hash)
        report["evidence_id"] = evidence_id
        return report
