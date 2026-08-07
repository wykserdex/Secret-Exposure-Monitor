"""Unit tests for scanning pipeline."""

import pytest
from unittest.mock import Mock, patch
import time

from secret_exposure_monitor.scanning.pipeline import ScanResult, ScannerEngine


class TestScanResult:
    """Tests for ScanResult dataclass."""

    def test_scan_result_creation(self):
        """Test creating a ScanResult."""
        result = ScanResult(
            findings=[{"type": "aws_key", "path": "config.py"}],
            files_scanned=5,
            lines_scanned=150,
            scan_duration_ms=234.5,
        )

        assert len(result.findings) == 1
        assert result.files_scanned == 5
        assert result.lines_scanned == 150
        assert result.scan_duration_ms == 234.5
        assert result.error is None

    def test_scan_result_with_error(self):
        """Test ScanResult with error."""
        result = ScanResult(
            findings=[],
            files_scanned=0,
            lines_scanned=0,
            scan_duration_ms=0,
            error="Timeout expired",
        )

        assert result.error == "Timeout expired"
        assert result.findings == []

    def test_scan_result_empty(self):
        """Test empty ScanResult."""
        result = ScanResult(
            findings=[],
            files_scanned=0,
            lines_scanned=0,
            scan_duration_ms=0,
        )

        assert result.files_scanned == 0
        assert not result.findings


class TestScannerEngine:
    """Tests for ScannerEngine abstract base class."""

    def test_scanner_engine_is_abstract(self):
        """Test that ScannerEngine cannot be instantiated directly."""
        with pytest.raises(TypeError):
            ScannerEngine()

    def test_scanner_engine_requires_implementation(self):
        """Test that all abstract methods must be implemented."""
        class IncompleteEngine(ScannerEngine):
            def scan_diff(self, diff: str, repo_path: str):
                pass
            # Missing scan_file and scan_history

        with pytest.raises(TypeError):
            IncompleteEngine()

    def test_complete_engine_implementation(self):
        """Test implementing all abstract methods."""
        class CompleteEngine(ScannerEngine):
            def scan_diff(self, diff: str, repo_path: str):
                return ScanResult([], 0, 0, 0)
            
            def scan_file(self, file_path: str, content: str):
                return ScanResult([], 0, 0, 0)
            
            def scan_history(self, repo_path: str, from_commit: str | None = None):
                return ScanResult([], 0, 0, 0)

        engine = CompleteEngine()
        assert isinstance(engine, ScannerEngine)
