"""Correlation contracts for Campaign Graph integration.

These models define graph-compatible events and relations that can be
consumed by the future Campaign Graph system.
"""

from datetime import datetime, timezone
from uuid import UUID, uuid4

from pydantic import BaseModel, Field


class GraphRelation(BaseModel):
    """Represents a relationship between two entities in the graph.
    
    All relations are tenant-scoped to prevent cross-tenant data leakage.
    """

    relation_id: UUID = Field(default_factory=uuid4)
    tenant_id: UUID

    source_type: str  # e.g., "Commit", "SecretFingerprint", "Domain"
    source_id: str    # Tenant-scoped identifier
    relation_type: str  # e.g., "EXPOSED", "BELONGS_TO_PROVIDER", "RELATED_TO"
    target_type: str
    target_id: str

    confidence: float = Field(ge=0, le=1)
    first_seen_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    last_seen_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    evidence_refs: list[UUID] = Field(default_factory=list)  # Finding IDs, etc.
    source_system: str  # e.g., "secret_exposure_monitor"
    expires_at: datetime | None = None  # For time-limited relations


class SecretExposureDetected(BaseModel):
    """Graph-friendly event for secret exposure detection.
    
    Security notes:
    - No raw secrets or full diffs included
    - fingerprint is tenant-specific HMAC
    - Designed for append-only event stores
    """

    schema_version: int = 1
    event_id: UUID = Field(default_factory=uuid4)
    correlation_id: UUID  # Groups related events
    tenant_id: UUID

    finding_id: UUID
    repository_id: UUID
    commit_sha: str
    secret_fingerprint: str
    secret_type: str
    provider: str | None

    severity: str
    confidence: float

    # Hints for graph correlation (no sensitive data)
    graph_hints: list[str] = Field(default_factory=list)
    # e.g., ["same_organization", "similar_commit_pattern", "related_domain"]

    occurred_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


# Relation types for Campaign Graph
RELATION_TYPES = {
    "CONTAINS_COMMIT": ("Repository", "Commit"),
    "EXPOSED": ("Commit", "SecretFingerprint"),
    "BELONGS_TO_PROVIDER": ("SecretFingerprint", "Provider"),
    "OBSERVED_IN": ("SecretFingerprint", "LeakIncident"),
    "RELATED_TO": ("Domain", "Campaign"),
    "TARGETS": ("Campaign", "Organization"),
    "OWNED_BY": ("Repository", "Organization"),
}
