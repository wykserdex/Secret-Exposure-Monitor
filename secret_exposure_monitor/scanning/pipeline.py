"""Scanning pipeline and utilities."""

from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Any


@dataclass
class ScanResult:
    """Result of scanning a file or diff."""

    findings: list[dict[str, Any]]
    files_scanned: int
    lines_scanned: int
    scan_duration_ms: float
    error: str | None = None


class ScannerEngine(ABC):
    """Abstract base class for secret scanning engines."""

    @abstractmethod
    def scan_diff(self, diff: str, repo_path: str) -> ScanResult:
        """Scan a git diff for secrets."""
        pass

    @abstractmethod
    def scan_file(self, file_path: str, content: str) -> ScanResult:
        """Scan a single file for secrets."""
        pass

    @abstractmethod
    def scan_history(self, repo_path: str, from_commit: str | None = None) -> ScanResult:
        """Scan git history for secrets."""
        pass
