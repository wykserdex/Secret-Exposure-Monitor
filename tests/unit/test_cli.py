"""Unit tests for CLI."""

import pytest
import json
from uuid import uuid4
from unittest.mock import patch, MagicMock

from secret_exposure_monitor.cli import main


class TestCLI:
    """Tests for CLI commands."""

    def test_scan_command_basic(self, capsys):
        """Test scan command with basic args."""
        tenant_id = str(uuid4())
        repo_id = str(uuid4())

        with patch("sys.argv", ["sem", "scan", "./test-repo", "--tenant-id", tenant_id, "--repository-id", repo_id]):
            main()

        captured = capsys.readouterr()
        assert f"Scanning ./test-repo for tenant {tenant_id}" in captured.out

    def test_scan_command_json_output(self, capsys):
        """Test scan command with JSON output."""
        tenant_id = str(uuid4())
        repo_id = str(uuid4())

        with patch("sys.argv", [
            "sem", "scan", "./repo",
            "--tenant-id", tenant_id,
            "--repository-id", repo_id,
            "--json"
        ]):
            main()

        captured = capsys.readouterr()
        # Should output valid JSON
        result = json.loads(captured.out.strip().split("\n")[-1])
        assert "status" in result

    def test_remediate_command(self, capsys):
        """Test remediate command."""
        finding = {
            "finding_id": str(uuid4()),
            "secret_type": "github_pat",
            "fingerprint": "v1:abc123"
        }

        with patch("sys.argv", [
            "sem", "remediate",
            "--finding-json", json.dumps(finding),
            "--approved-by", "test-user"
        ]):
            main()

        captured = capsys.readouterr()
        assert "Remediating finding" in captured.out

    def test_help_command(self, capsys):
        """Test help output."""
        with patch("sys.argv", ["sem", "--help"]):
            with pytest.raises(SystemExit):
                main()

        captured = capsys.readouterr()
        assert "scan" in captured.out
        assert "remediate" in captured.out

    def test_no_command_shows_help(self, capsys):
        """Test that no command shows help."""
        with patch("sys.argv", ["sem"]):
            with pytest.raises(SystemExit):
                main()

        captured = capsys.readouterr()
        assert "usage:" in captured.out.lower() or "Available commands" in captured.out
