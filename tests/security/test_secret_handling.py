"""Security tests for secret handling."""

import pytest
import hmac
import hashlib

from secret_exposure_monitor.domain.secret import secret_fingerprint, redact_secret
from secret_exposure_monitor.domain.finding import SecretFinding
from uuid import uuid4


class TestSecretFingerprintSecurity:
    """Security tests for fingerprint generation."""

    def test_fingerprint_uses_hmac(self):
        """Verify fingerprint uses HMAC-SHA256."""
        tenant_key = b"test-key"
        secret = b"ghp_test123"
        
        fp = secret_fingerprint(secret, tenant_key=tenant_key)
        
        # Format should be version:hex_digest
        parts = fp.split(":")
        assert len(parts) == 2
        assert parts[0] == "v1"
        assert len(parts[1]) == 64  # SHA256 hex length
        
        # Verify it's actually HMAC
        expected = hmac.new(tenant_key, secret, hashlib.sha256).hexdigest()
        assert parts[1] == expected

    def test_fingerprint_tenant_isolation(self):
        """Test that different tenants get different fingerprints for same secret."""
        secret = b"ghp_same_secret_value"
        
        tenant_a_key = b"tenant-a-key"
        tenant_b_key = b"tenant-b-key"
        
        fp_a = secret_fingerprint(secret, tenant_key=tenant_a_key)
        fp_b = secret_fingerprint(secret, tenant_key=tenant_b_key)
        
        # Fingerprints must differ between tenants
        assert fp_a != fp_b
        
        # Prevents cross-tenant correlation in Campaign Graph

    def test_fingerprint_key_rotation(self):
        """Test key version support for rotation."""
        secret = b"ghp_secret"
        tenant_key = b"key"
        
        fp_v1 = secret_fingerprint(secret, tenant_key=tenant_key, key_version="v1")
        fp_v2 = secret_fingerprint(secret, tenant_key=tenant_key, key_version="v2")
        
        assert fp_v1.startswith("v1:")
        assert fp_v2.startswith("v2:")
        assert fp_v1 != fp_v2

    def test_fingerprint_deterministic_same_key(self):
        """Same secret + same key = same fingerprint (for deduplication)."""
        secret = b"ghp_test"
        key = b"tenant-key"
        
        fp1 = secret_fingerprint(secret, tenant_key=key)
        fp2 = secret_fingerprint(secret, tenant_key=key)
        fp3 = secret_fingerprint(secret, tenant_key=key)
        
        assert fp1 == fp2 == fp3

    def test_short_secrets_fingerprinted(self):
        """Test that even short secrets can be fingerprinted."""
        short_secret = b"abc"
        key = b"test"
        
        fp = secret_fingerprint(short_secret, tenant_key=key)
        
        assert ":" in fp
        assert len(fp.split(":")[1]) == 64


class TestRedactionSecurity:
    """Security tests for secret redaction."""

    def test_redact_prevents_full_exposure(self):
        """Verify redacted output never contains full secret."""
        secret = "ghp_abcdefghij1234567890xyz"
        redacted = redact_secret(secret)
        
        assert secret not in redacted
        assert "…" in redacted

    def test_redact_short_values_fully_hidden(self):
        """Short secrets should be fully redacted."""
        short_secrets = ["ab", "abc", "abcd", "abcde"]
        
        for s in short_secrets:
            result = redact_secret(s)
            assert result == "[REDACTED]"

    def test_redact_custom_visible_chars(self):
        """Test custom visible character count."""
        secret = "0123456789abcdef"
        
        result_2 = redact_secret(secret, visible_chars=2)
        assert result_2.startswith("01")
        assert result_2.endswith("ef")
        
        result_6 = redact_secret(secret, visible_chars=6)
        assert result_6.startswith("012345")
        assert result_6.endswith("abcdef")

    def test_redact_github_token_pattern(self):
        """Test redaction preserves GitHub token prefix safely."""
        # GitHub PAT format: ghp_XXXXXXXXXXXXXXXXXXXX
        token = "ghp_AbcDefGhiJklMnoPqrSt"
        redacted = redact_secret(token)
        
        # Should show first 4 chars (ghp_) and last 4
        assert redacted.startswith("ghp_")
        assert len(redacted) < len(token)

    def test_no_raw_secret_in_finding_model(self):
        """Verify SecretFinding model has no raw_secret field."""
        schema = SecretFinding.model_json_schema()
        properties = schema.get("properties", {})
        
        forbidden_fields = [
            "raw_secret",
            "secret_value", 
            "token",
            "password",
            "api_key",
            "full_line",
            "full_diff",
        ]
        
        for field in forbidden_fields:
            assert field not in properties, f"Forbidden field '{field}' found in SecretFinding schema"


class TestTenantIsolation:
    """Tests for tenant isolation security."""

    def test_finding_requires_tenant_id(self):
        """Every finding must have a tenant_id for isolation."""
        with pytest.raises(Exception):  # pydantic validation error
            SecretFinding(
                repository_id=uuid4(),
                commit_sha="abc123",
                path="test.py",
                secret_type="github_pat",
                fingerprint="v1:hash",
                redacted_preview="ghp_****xyz",
                confidence=0.9,
                severity="high",
                detector="gitleaks",
                detector_version="1.0",
                rule_id="github-pat",
            )

    def test_repository_requires_tenant_id(self):
        """Every repository must have a tenant_id for isolation."""
        from secret_exposure_monitor.domain.repository import Repository, RepoProvider
        
        with pytest.raises(Exception):
            Repository(
                repository_id=uuid4(),
                provider=RepoProvider.GITHUB,
                external_id="123",
                name="test-repo",
                full_name="org/test",
            )

    def test_graph_relation_requires_tenant_id(self):
        """Graph relations must be tenant-scoped."""
        from secret_exposure_monitor.correlation_contracts.events import GraphRelation
        
        with pytest.raises(Exception):
            GraphRelation(
                source_type="Commit",
                source_id="abc",
                relation_type="EXPOSED",
                target_type="SecretFingerprint",
                target_id="v1:hash",
                confidence=0.9,
                source_system="sem",
            )
