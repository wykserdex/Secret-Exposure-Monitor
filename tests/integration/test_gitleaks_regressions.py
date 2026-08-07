"""Regression tests for GitleaksEngine bugs found and fixed:

1. scan_diff() used to ignore its own `diff` argument entirely — it wrote
   the diff text to a temp file that was never referenced in the actual
   subprocess call, which instead scanned `repo_path` as a directory via
   `--source`. A function named scan_diff wasn't scanning the diff at all.
2. _normalize_findings() used to carry the raw matched secret text forward
   under a `raw_match` key, with nothing downstream ever fingerprinting or
   redacting it.

These use unittest.mock to inspect the actual subprocess.run() call
without requiring a real gitleaks binary in the test environment.
"""

from pathlib import Path
from unittest.mock import patch, MagicMock

from secret_exposure_monitor.scanning.engines.gitleaks import GitleaksEngine


class TestScanDiffActuallyUsesDiff:
    def test_diff_text_passed_via_stdin(self):
        """scan_diff must feed the diff text to the subprocess somehow —
        previously it was written to a file that was never referenced by
        the gitleaks command at all."""
        engine = GitleaksEngine(gitleaks_path="gitleaks")
        diff_text = "+new_code_with_secret_ghp_1234567890abcdef"

        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0)
            engine.scan_diff(diff_text, "/some/repo")

        assert mock_run.called
        _, kwargs = mock_run.call_args
        assert kwargs.get("input") == diff_text

    def test_uses_pipe_flag_not_source(self):
        """Confirms the fix: scan_diff scans the piped text (--pipe), not
        an arbitrary directory (--source), which is what it silently did
        before regardless of what `diff` contained."""
        engine = GitleaksEngine(gitleaks_path="gitleaks")

        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0)
            engine.scan_diff("some diff", "/some/repo")

        args, _ = mock_run.call_args
        cmd = args[0]
        assert "--pipe" in cmd
        assert "--source" not in cmd


class TestNormalizeFindingsNeverLeaksSecret:
    def test_no_raw_match_key(self):
        engine = GitleaksEngine()
        raw_findings = [{
            "RuleID": "github-pat",
            "File": "config.py",
            "StartLine": 42,
            "Match": "ghp_abc123xyz789REALSECRET",
        }]

        normalized = engine._normalize_findings(raw_findings)

        assert "raw_match" not in normalized[0]

    def test_secret_value_not_present_anywhere_in_output(self):
        """Belt-and-suspenders: the actual secret string shouldn't appear
        in any value of the normalized dict, not just under a specific
        key name."""
        engine = GitleaksEngine()
        secret_value = "ghp_abc123xyz789REALSECRET"
        raw_findings = [{
            "RuleID": "github-pat",
            "File": "config.py",
            "StartLine": 42,
            "Match": secret_value,
        }]

        normalized = engine._normalize_findings(raw_findings)

        for value in normalized[0].values():
            assert secret_value not in str(value)

    def test_still_reports_useful_metadata(self):
        """Removing the raw match shouldn't remove everything useful —
        secret_type/path/line_number/confidence must still be present."""
        engine = GitleaksEngine()
        raw_findings = [{
            "RuleID": "github-pat",
            "File": "config.py",
            "StartLine": 42,
            "Match": "ghp_abc123xyz789",
        }]

        normalized = engine._normalize_findings(raw_findings)

        assert normalized[0]["secret_type"] == "github-pat"
        assert normalized[0]["path"] == "config.py"
        assert normalized[0]["line_number"] == 42
        assert normalized[0]["confidence"] == 0.8
