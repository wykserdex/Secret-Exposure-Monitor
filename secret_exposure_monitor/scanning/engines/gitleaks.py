"""Gitleaks engine integration."""

import json
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
        """
        Scan a git diff (unified diff text) for secrets using Gitleaks.

        Uses `--pipe` to feed the diff via stdin, per Gitleaks' own
        documented usage (`cat some_file | gitleaks detect --pipe`).

        Note: `repo_path` is currently unused. The previous version of this
        method wrote `diff` to a temp file and then never referenced that
        file in the actual subprocess call — it ran
        `gitleaks detect --source repo_path --no-git`, which scans
        repo_path as a directory and silently ignores the diff text
        entirely. A function named scan_diff was, in practice, scanning
        whatever repo_path happened to contain instead of the diff passed
        to it.
        """
        start_time = time.time()

        with tempfile.TemporaryDirectory() as tmpdir:
            report_path = Path(tmpdir) / "report.json"

            try:
                subprocess.run(
                    [
                        self.gitleaks_path,
                        "detect",
                        "--no-git",
                        "--pipe",
                        "--report-path",
                        str(report_path),
                        "--report-format",
                        "json",
                    ],
                    input=diff,
                    capture_output=True,
                    text=True,
                    timeout=60,
                )

                findings = self._load_report(report_path)
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
        """
        Scan a single file's content for secrets.

        Writes content to a temp dir and runs a directory scan against it
        (`--source <tmpdir> --no-git`). This is intentionally separate
        from scan_diff now — it used to delegate to scan_diff(""), which
        only happened to work because scan_diff's own --source-based
        implementation ignored the diff argument anyway. Now that
        scan_diff properly scans diff text via --pipe, that delegation
        would no longer make sense.
        """
        start_time = time.time()

        with tempfile.TemporaryDirectory() as tmpdir:
            target_file = Path(tmpdir) / (Path(file_path).name or "scanned_file")
            target_file.write_text(content)
            report_path = Path(tmpdir) / "report.json"

            try:
                subprocess.run(
                    [
                        self.gitleaks_path,
                        "detect",
                        "--source",
                        tmpdir,
                        "--no-git",
                        "--report-path",
                        str(report_path),
                        "--report-format",
                        "json",
                    ],
                    capture_output=True,
                    text=True,
                    timeout=60,
                )

                findings = self._load_report(report_path)
                duration_ms = (time.time() - start_time) * 1000

                return ScanResult(
                    findings=findings,
                    files_scanned=1,
                    lines_scanned=content.count("\n"),
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

    def scan_history(self, repo_path: str, from_commit: str | None = None) -> ScanResult:
        """Scan git history for secrets."""
        start_time = time.time()

        with tempfile.TemporaryDirectory() as tmpdir:
            report_path = Path(tmpdir) / "report.json"
            cmd = [
                self.gitleaks_path,
                "detect",
                "--source",
                repo_path,
                "--report-path",
                str(report_path),
                "--report-format",
                "json",
            ]

            if from_commit:
                cmd.extend(["--log-opts", f"{from_commit}..HEAD"])

            try:
                subprocess.run(
                    cmd,
                    capture_output=True,
                    text=True,
                    timeout=300,  # History scans can take longer
                )

                findings = self._load_report(report_path)
                duration_ms = (time.time() - start_time) * 1000

                return ScanResult(
                    findings=findings,
                    files_scanned=0,
                    lines_scanned=0,
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

    def _load_report(self, report_path: Path) -> list[dict]:
        """Load and normalize a Gitleaks JSON report, if one was written."""
        if not report_path.exists():
            return []
        raw = json.loads(report_path.read_text())
        return self._normalize_findings(raw)

    def _normalize_findings(self, raw_findings: list[dict]) -> list[dict]:
        """
        Normalize Gitleaks findings to internal format.

        SECURITY: Deliberately does not carry the matched secret text
        forward. The previous version stored `finding.get("Match", "")`
        under a `raw_match` key in the returned dict — Gitleaks' "Match"
        field contains the actual matched secret substring, so that dict
        (typed as ScanResult.findings: list[dict[str, Any]], with no
        schema enforcement) was carrying raw secret values with no
        fingerprinting or redaction applied anywhere downstream. There was
        no code anywhere in this codebase that converted these dicts into
        a safe SecretFinding, so the raw value would have sat unprotected
        in whatever consumed ScanResult (logs, API responses, etc.) the
        moment someone wired one up.
        """
        normalized = []

        for finding in raw_findings:
            match_text = finding.get("Match", "")
            normalized.append({
                "secret_type": finding.get("RuleID", "unknown"),
                "path": finding.get("File", ""),
                "line_number": finding.get("StartLine"),
                "confidence": 0.8,  # Gitleaks doesn't provide confidence
                "match_length": len(match_text),  # for triage, not the value itself
            })

        return normalized
