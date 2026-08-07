"""Remediation domain models."""

from datetime import datetime, timezone
from enum import StrEnum
from uuid import UUID, uuid4

from pydantic import BaseModel, Field


class RemediationAction(StrEnum):
    """Available remediation actions."""

    REVOKE = "revoke"
    ROTATE = "rotate"
    DELETE_FROM_FILE = "delete_from_file"
    CLEAN_HISTORY = "clean_history"
    NOTIFY = "notify"


class RemediationStatus(StrEnum):
    """Status of a remediation workflow."""

    PENDING = "pending"
    IN_PROGRESS = "in_progress"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class RemediationPlaybook(BaseModel):
    """Defines steps for remediating a specific secret type."""

    playbook_id: UUID = Field(default_factory=uuid4)
    secret_type: str
    # Optional: some secret types have no identifiable provider (e.g. a
    # generic high-entropy string). Kept required (str) in an earlier draft
    # of this same project — instantiating a playbook for such a type
    # crashed with a ValidationError every time. Nothing currently
    # constructs a RemediationPlaybook in this codebase, so it hasn't bitten
    # yet, but it's the same landmine, fixed proactively before something
    # does construct one.
    provider: str | None = None

    steps: list[RemediationAction]
    auto_execute: bool = False  # Requires manual approval if False
    requires_backup: bool = True
    notify_channels: list[str] = Field(default_factory=list)

    # Rate limiting
    max_attempts: int = 3
    timeout_seconds: int = 300


class RemediationWorkflow(BaseModel):
    """Tracks execution of a remediation workflow."""

    workflow_id: UUID = Field(default_factory=uuid4)
    finding_id: UUID
    tenant_id: UUID

    playbook_id: UUID
    status: RemediationStatus = RemediationStatus.PENDING

    approved_by: str | None = None
    approved_at: datetime | None = None

    executed_steps: list[str] = Field(default_factory=list)
    error_message: str | None = None

    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    completed_at: datetime | None = None
