"""Unit tests for domain models."""

import pytest
from uuid import uuid4
from datetime import datetime, timezone

from secret_exposure_monitor.domain.finding import FindingStatus, SecretFinding, ConfidenceLevel
from secret_exposure_monitor.domain.repository import Repository, RepoProvider
from secret_exposure_monitor.domain.secret import secret_fingerprint, redact_secret
from secret_exposure_monitor.domain.remediation import (
    RemediationAction,
    RemediationPlaybook,
    RemediationWorkflow,
)


class TestSecretFinding:
    """Tests for SecretFinding model."""

    def test_create_finding(self):
        """Test creating a valid finding."""
        finding = SecretFinding(
            tenant_id=uuid4(),
            repository_id=uuid4(),
            commit_sha="abc123",
            path="config.py",
            line_number=42,
            secret_type="github_personal_access_token",
            fingerprint="v1:abcd1234",
            redacted_preview="ghp_****xyz",
            confidence=0.95,
            severity="high",
            detector="gitleaks",
            detector_version="8.18.0",
            rule_id="github-pat",
        )

        assert finding.status == FindingStatus.OPEN
        assert finding.confidence == 0.95
        assert finding.line_number == 42

    def test_finding_default_status(self):
        """Test that new findings have OPEN status."""
        finding = SecretFinding(
            tenant_id=uuid4(),
            repository_id=uuid4(),
            commit_sha="abc123",
            path="test.py",
            secret_type="aws_key",
            fingerprint="v1:hash",
            redacted_preview="[REDACTED]",
            confidence=0.8,
            severity="medium",
            detector="gitleaks",
            detector_version="1.0",
            rule_id="aws",
        )

        assert finding.status == FindingStatus.OPEN

    def test_finding_with_optional_line_number(self):
        """Test finding without line number."""
        finding = SecretFinding(
            tenant_id=uuid4(),
            repository_id=uuid4(),
            commit_sha="abc123",
            path=".env",
            secret_type="generic",
            fingerprint="v1:hash",
            redacted_preview="[REDACTED]",
            confidence=0.7,
            severity="low",
            detector="gitleaks",
            detector_version="1.0",
            rule_id="generic",
        )

        assert finding.line_number is None


class TestRepository:
    """Tests for Repository model."""

    def test_create_repository(self):
        """Test creating a repository."""
        repo = Repository(
            repository_id=uuid4(),
            tenant_id=uuid4(),
            provider=RepoProvider.GITHUB,
            external_id="123456",
            name="my-repo",
            full_name="org/my-repo",
            is_private=True,
        )

        assert repo.provider == RepoProvider.GITHUB
        assert repo.is_private is True
        assert repo.default_branch == "main"
        assert repo.scan_enabled is True

    def test_repository_allowed_branches(self):
        """Test default allowed branches."""
        repo = Repository(
            repository_id=uuid4(),
            tenant_id=uuid4(),
            provider=RepoProvider.GITLAB,
            external_id="789",
            name="test",
            full_name="group/test",
        )

        assert "main" in repo.allowed_branches
        assert "master" in repo.allowed_branches


class TestSecretUtilities:
    """Tests for secret utility functions."""

    def test_fingerprint_deterministic(self):
        """Test fingerprint is deterministic with same key."""
        tenant_key = b"test-key-123"
        secret = b"ghp_test123456"

        fp1 = secret_fingerprint(secret, tenant_key=tenant_key)
        fp2 = secret_fingerprint(secret, tenant_key=tenant_key)

        assert fp1 == fp2

    def test_fingerprint_different_keys(self):
        """Test different keys produce different fingerprints."""
        secret = b"ghp_test123456"

        fp1 = secret_fingerprint(secret, tenant_key=b"key1")
        fp2 = secret_fingerprint(secret, tenant_key=b"key2")

        assert fp1 != fp2

    def test_fingerprint_format(self):
        """Test fingerprint includes version prefix."""
        fp = secret_fingerprint(b"secret", tenant_key=b"key", key_version="v2")

        assert fp.startswith("v2:")
        assert len(fp.split(":")[1]) == 64  # SHA256 hex length

    def test_redact_short_secret(self):
        """Test redaction of short secrets."""
        result = redact_secret("abc")
        assert result == "[REDACTED]"

    def test_redact_long_secret(self):
        """Test redaction of longer secrets."""
        result = redact_secret("ghp_abcdefghij1234567890")
        assert "…" in result
        assert result.startswith("ghp_")

    def test_redact_preserves_edges(self):
        """Test redaction preserves start and end characters."""
        secret = "abcdefghij1234"
        result = redact_secret(secret, visible_chars=4)

        assert result.startswith(secret[:4])
        assert result.endswith(secret[-4:])


class TestRemediationWorkflow:
    """Tests for remediation workflow."""

    def test_create_workflow(self):
        """Test creating a remediation workflow."""
        workflow = RemediationWorkflow(
            finding_id=uuid4(),
            tenant_id=uuid4(),
            playbook_id=uuid4(),
        )

        assert workflow.status.value == "pending"
        assert workflow.approved_by is None
        assert workflow.executed_steps == []

    def test_remediation_actions(self):
        """Test remediation action enum values."""
        assert RemediationAction.REVOKE.value == "revoke"
        assert RemediationAction.ROTATE.value == "rotate"
        assert RemediationAction.NOTIFY.value == "notify"


class TestRemediationPlaybook:
    """RemediationPlaybook wasn't imported by any test before this — its
    `provider` field used to be required (`str`), which is fine for
    provider-specific secrets (github_pat, aws_access_key) but would raise
    a ValidationError for any secret type with no identifiable provider
    (e.g. a generic high-entropy string). This exact bug previously broke
    an equivalent RemediationOrchestrator in an earlier version of this
    project — nothing in *this* version constructs a playbook yet, so it
    hadn't bitten, but it's the same landmine."""

    def test_playbook_with_provider(self):
        playbook = RemediationPlaybook(
            secret_type="github_personal_access_token",
            provider="github",
            steps=[RemediationAction.REVOKE, RemediationAction.NOTIFY],
        )
        assert playbook.provider == "github"

    def test_playbook_without_provider(self):
        """Generic/unknown secret types have no provider to key off of."""
        playbook = RemediationPlaybook(
            secret_type="generic_high_entropy_string",
            steps=[RemediationAction.NOTIFY],
        )
        assert playbook.provider is None


class TestConfidenceLevel:
    """Tests for confidence classification."""

    def test_confidence_levels(self):
        """Test all confidence levels exist."""
        assert ConfidenceLevel.CONFIRMED_FORMAT.value == "confirmed_format"
        assert ConfidenceLevel.LIKELY_SECRET.value == "likely_secret"
        assert ConfidenceLevel.FALSE_POSITIVE.value == "false_positive"
