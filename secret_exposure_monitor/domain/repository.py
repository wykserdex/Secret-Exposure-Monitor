"""Repository domain models."""

from datetime import datetime, timezone
from enum import StrEnum
from uuid import UUID

from pydantic import BaseModel, Field


class RepoProvider(StrEnum):
    """Supported Git repository providers."""

    GITHUB = "github"
    GITLAB = "gitlab"
    GITEA = "gitea"
    LOCAL = "local"


class Repository(BaseModel):
    """Represents a monitored repository."""

    repository_id: UUID
    tenant_id: UUID
    provider: RepoProvider
    external_id: str  # Provider's repository ID
    name: str
    full_name: str  # e.g., "org/repo"
    is_private: bool = True
    default_branch: str = "main"

    # Monitoring settings
    scan_enabled: bool = True
    scan_history: bool = False
    allowed_branches: list[str] = Field(default_factory=lambda: ["main", "master"])

    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
