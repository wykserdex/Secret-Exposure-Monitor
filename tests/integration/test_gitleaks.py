"""Integration tests for scanning engines."""

import pytest
import tempfile
from pathlib import Path

from secret_exposure_monitor.scanning.engines.gitleaks import GitleaksEngine
from secret_exposure_monitor.scanning.pipeline import ScanResult


class TestGitleaksEngine:
    """Tests for GitleaksEngine integration."""

    def test_engine_initialization(self):
        """Test GitleaksEngine can be initialized."""
        engine = GitleaksEngine(gitleaks_path="gitleaks")
        assert engine.gitleaks_path == "gitleaks"

    def test_scan_diff_no_gitleaks_installed(self):
        """Test scan_diff handles missing gitleaks binary gracefully."""
        engine = GitleaksEngine(gitleaks_path="/nonexistent/gitleaks")
        
        diff = """diff --git a/test.py b/test.py
index abc123..def456 100644
--- a/test.py
+++ b/test.py
@@ -1 +1 @@
-old_code
+new_code_with_secret_ghp_1234567890abcdef
"""
        
        result = engine.scan_diff(diff, "/tmp/repo")
        
        # Should return error but not crash
        assert isinstance(result, ScanResult)
        assert result.error is not None or result.files_scanned == 0

    def test_scan_file_no_gitleaks_installed(self):
        """Test scan_file handles missing gitleaks binary gracefully."""
        engine = GitleaksEngine(gitleaks_path="/nonexistent/gitleaks")
        
        content = "AWS_SECRET_KEY = AKIAIOSFODNN7EXAMPLE"
        result = engine.scan_file("/tmp/config.py", content)
        
        assert isinstance(result, ScanResult)

    def test_scan_history_no_gitleaks_installed(self):
        """Test scan_history handles missing gitleaks binary gracefully."""
        engine = GitleaksEngine(gitleaks_path="/nonexistent/gitleaks")
        
        with tempfile.TemporaryDirectory() as tmpdir:
            result = engine.scan_history(tmpdir)
            
            assert isinstance(result, ScanResult)

    def test_normalize_findings(self):
        """Test _normalize_findings converts Gitleaks output."""
        engine = GitleaksEngine()
        
        raw_findings = [
            {
                "RuleID": "github-pat",
                "File": "config.py",
                "StartLine": 42,
                "Match": "ghp_abc123xyz789",
            },
            {
                "RuleID": "aws-secret",
                "File": ".env",
                "StartLine": 5,
                "Match": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
            },
        ]
        
        normalized = engine._normalize_findings(raw_findings)
        
        assert len(normalized) == 2
        assert normalized[0]["secret_type"] == "github-pat"
        assert normalized[0]["path"] == "config.py"
        assert normalized[0]["line_number"] == 42
        assert normalized[0]["confidence"] == 0.8
        
        assert normalized[1]["secret_type"] == "aws-secret"
        assert normalized[1]["path"] == ".env"

    def test_normalize_empty_findings(self):
        """Test _normalize_findings with empty input."""
        engine = GitleaksEngine()
        
        normalized = engine._normalize_findings([])
        
        assert normalized == []

    def test_normalize_missing_fields(self):
        """Test _normalize_findings handles missing fields."""
        engine = GitleaksEngine()
        
        raw_findings = [
            {"OtherField": "value"},  # Missing expected fields
        ]
        
        normalized = engine._normalize_findings(raw_findings)
        
        assert len(normalized) == 1
        assert normalized[0]["secret_type"] == "unknown"
        assert normalized[0]["path"] == ""
