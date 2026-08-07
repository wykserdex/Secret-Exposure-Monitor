"""Unit tests for correlation contracts."""

import pytest
from uuid import uuid4
from datetime import datetime, timezone

from secret_exposure_monitor.correlation_contracts.events import (
    GraphRelation,
    SecretExposureDetected,
    RELATION_TYPES,
)


class TestGraphRelation:
    """Tests for GraphRelation model."""

    def test_create_relation(self):
        """Test creating a graph relation."""
        relation = GraphRelation(
            tenant_id=uuid4(),
            source_type="Commit",
            source_id="abc123",
            relation_type="EXPOSED",
            target_type="SecretFingerprint",
            target_id="v1:hash123",
            confidence=0.9,
            source_system="secret_exposure_monitor",
        )

        assert relation.relation_type == "EXPOSED"
        assert relation.confidence == 0.9
        assert relation.evidence_refs == []

    def test_relation_with_evidence(self):
        """Test relation with evidence references."""
        evidence_ids = [uuid4(), uuid4()]

        relation = GraphRelation(
            tenant_id=uuid4(),
            source_type="Repository",
            source_id="repo-1",
            relation_type="OWNED_BY",
            target_type="Organization",
            target_id="org-1",
            confidence=1.0,
            evidence_refs=evidence_ids,
            source_system="secret_exposure_monitor",
        )

        assert len(relation.evidence_refs) == 2
        assert relation.confidence == 1.0

    def test_relation_expires_at(self):
        """Test relation with expiration."""
        expires = datetime.now(timezone.utc)

        relation = GraphRelation(
            tenant_id=uuid4(),
            source_type="Domain",
            source_id="example.com",
            relation_type="RELATED_TO",
            target_type="Campaign",
            target_id="camp-1",
            confidence=0.7,
            source_system="secret_exposure_monitor",
            expires_at=expires,
        )

        assert relation.expires_at == expires


class TestSecretExposureDetected:
    """Tests for SecretExposureDetected event."""

    def test_create_event(self):
        """Test creating a detection event."""
        event = SecretExposureDetected(
            correlation_id=uuid4(),
            tenant_id=uuid4(),
            finding_id=uuid4(),
            repository_id=uuid4(),
            commit_sha="abc123def",
            secret_fingerprint="v1:abcd1234",
            secret_type="github_personal_access_token",
            provider="github",
            severity="high",
            confidence=0.95,
        )

        assert event.secret_type == "github_personal_access_token"
        assert event.confidence == 0.95
        assert event.graph_hints == []

    def test_event_with_graph_hints(self):
        """Test event with correlation hints."""
        event = SecretExposureDetected(
            correlation_id=uuid4(),
            tenant_id=uuid4(),
            finding_id=uuid4(),
            repository_id=uuid4(),
            commit_sha="abc123",
            secret_fingerprint="v1:hash",
            secret_type="aws_key",
            provider="aws",
            severity="medium",
            confidence=0.8,
            graph_hints=["same_organization", "similar_commit_pattern"],
        )

        assert len(event.graph_hints) == 2
        assert "same_organization" in event.graph_hints

    def test_event_no_raw_secrets(self):
        """Verify event schema has no raw secret fields."""
        # This is a schema validation test
        event_schema = SecretExposureDetected.model_json_schema()
        properties = event_schema.get("properties", {})

        forbidden_fields = ["raw_secret", "full_diff", "secret_value", "token"]
        for field in forbidden_fields:
            assert field not in properties


class TestRelationTypes:
    """Tests for predefined relation types."""

    def test_relation_types_defined(self):
        """Test all expected relation types exist."""
        assert "EXPOSED" in RELATION_TYPES
        assert "BELONGS_TO_PROVIDER" in RELATION_TYPES
        assert "CONTAINS_COMMIT" in RELATION_TYPES

    def test_relation_type_structure(self):
        """Test relation type defines source and target."""
        exposed_relation = RELATION_TYPES["EXPOSED"]
        assert exposed_relation == ("Commit", "SecretFingerprint")

        belongs_relation = RELATION_TYPES["BELONGS_TO_PROVIDER"]
        assert belongs_relation == ("SecretFingerprint", "Provider")
