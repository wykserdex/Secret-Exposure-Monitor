"""Domain models for Secret Exposure Monitor."""

from datetime import datetime, timezone
from enum import StrEnum
from uuid import UUID, uuid4

from pydantic import BaseModel, Field


class FindingStatus(StrEnum):
    """Status of a secret finding."""

    OPEN = "open"
    ACKNOWLEDGED = "acknowledged"
    REVOKED = "revoked"
    ROTATED = "rotated"
    FALSE_POSITIVE = "false_positive"
    RESOLVED = "resolved"


class SecretFinding(BaseModel):
    """Represents a detected secret exposure.
    
    Security notes:
    - Never store raw_secret in this model
    - fingerprint uses HMAC with tenant-specific key
    - redacted_preview shows only safe portions
    """

    schema_version: int = 1
    finding_id: UUID = Field(default_factory=uuid4)

    # Context
    tenant_id: UUID
    repository_id: UUID
    commit_sha: str
    path: str
    line_number: int | None = None

    # Secret identification (never raw value)
    secret_type: str
    provider: str | None = None
    fingerprint: str  # HMAC-SHA256 with tenant key
    redacted_preview: str  # e.g., "ghp_****b82a"

    # Classification
    confidence: float = Field(ge=0, le=1)
    severity: str
    status: FindingStatus = FindingStatus.OPEN

    # Detection metadata
    detector: str
    detector_version: str
    rule_id: str

    # Timestamps
    first_seen_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class ConfidenceLevel(StrEnum):
    """Confidence classification for detected secrets."""

    CONFIRMED_FORMAT = "confirmed_format"
    LIKELY_SECRET = "likely_secret"
    GENERIC_HIGH_ENTROPY = "generic_high_entropy"
    TEST_FIXTURE = "test_fixture"
    PLACEHOLDER = "placeholder"
    FALSE_POSITIVE = "false_positive"
