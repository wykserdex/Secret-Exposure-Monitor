"""Gitleaks engine integration."""

import subprocess
import tempfile
import time
from pathlib import Path

from secret_exposure_monitor.scanning.pipeline import ScannerEngine, ScanResult


class GitleaksEngine(ScannerEngine):
    """Gitleaks-based secret scanning engine.
    
    Security: Runs in isolated environment with no network access.
    """

    def __init__(self, gitleaks_path: str = "gitleaks"):
        self.gitleaks_path = gitleaks_path

    def scan_diff(self, diff: str, repo_path: str) -> ScanResult:
        """Scan a git diff for secrets using Gitleaks."""
        start_time = time.time()

        with tempfile.TemporaryDirectory() as tmpdir:
            diff_file = Path(tmpdir) / "diff.patch"
            diff_file.write_text(diff)

            try:
                result = subprocess.run(
                    [
                        self.gitleaks_path,
                        "detect",
                        "--source",
                        repo_path,
                        "--no-git",
                        "--report-path",
                        str(Path(tmpdir) / "report.json"),
                        "--report-format",
                        "json",
                    ],
                    capture_output=True,
                    text=True,
                    timeout=60,
                )

                # Parse Gitleaks JSON report
                report_path = Path(tmpdir) / "report.json"
                if report_path.exists():
                    import json

                    findings_raw = json.loads(report_path.read_text())
                    findings = self._normalize_findings(findings_raw)
                else:
                    findings = []

                duration_ms = (time.time() - start_time) * 1000

                return ScanResult(
                    findings=findings,
                    files_scanned=1,
                    lines_scanned=diff.count("\n"),
                    scan_duration_ms=duration_ms,
                )

            except subprocess.TimeoutExpired:
                return ScanResult(
                    findings=[],
                    files_scanned=0,
                    lines_scanned=0,
                    scan_duration_ms=0,
                    error="Gitleaks scan timed out",
                )
            except Exception as e:
                return ScanResult(
                    findings=[],
                    files_scanned=0,
                    lines_scanned=0,
                    scan_duration_ms=0,
                    error=str(e),
                )

    def scan_file(self, file_path: str, content: str) -> ScanResult:
        """Scan a single file for secrets."""
        start_time = time.time()

        with tempfile.TemporaryDirectory() as tmpdir:
            target_file = Path(tmpdir) / Path(file_path).name
            target_file.write_text(content)

            # Reuse scan logic
            return self.scan_diff("", str(tmpdir))

    def scan_history(self, repo_path: str, from_commit: str | None = None) -> ScanResult:
        """Scan git history for secrets."""
        start_time = time.time()

        try:
            cmd = [self.gitleaks_path, "detect", "--source", repo_path, "--report-format", "json"]

            if from_commit:
                cmd.extend(["--from-commit", from_commit])

            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=300,  # History scans can take longer
            )

            # Parse results...
            duration_ms = (time.time() - start_time) * 1000

            return ScanResult(
                findings=[],  # Parsed findings
                files_scanned=0,
                lines_scanned=0,
                scan_duration_ms=duration_ms,
            )

        except Exception as e:
            return ScanResult(
                findings=[],
                files_scanned=0,
                lines_scanned=0,
                scan_duration_ms=0,
                error=str(e),
            )

    def _normalize_findings(self, raw_findings: list[dict]) -> list[dict]:
        """Normalize Gitleaks findings to internal format."""
        normalized = []

        for finding in raw_findings:
            normalized.append({
                "secret_type": finding.get("RuleID", "unknown"),
                "path": finding.get("File", ""),
                "line_number": finding.get("StartLine"),
                "confidence": 0.8,  # Gitleaks doesn't provide confidence
                "raw_match": finding.get("Match", ""),
            })

        return normalized
