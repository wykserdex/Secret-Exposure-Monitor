# Secret Exposure Monitor

Detect, classify, and remediate exposed secrets in Git repositories with Campaign Graph integration.

## Features

- **Multi-provider support**: GitHub, GitLab, Gitea, and local repositories
- **Secure scanning**: HMAC fingerprinting, no raw secrets stored
- **Gitleaks integration**: Industry-standard secret detection engine
- **Remediation workflows**: Revoke, rotate, and clean up exposed secrets
- **Campaign Graph ready**: Graph-compatible events for future correlation
- **Security-first**: Isolated scanner, redacted logs, tenant isolation

## Installation

```bash
pip install -e .
```

## CLI Usage

```bash
# Show help
sem --help

# Scan a repository
sem scan ./my-repo --tenant-id <uuid> --repository-id <uuid>

# Scan with JSON output
sem scan ./my-repo --tenant-id <uuid> --repository-id <uuid> --json

# Scan git history
sem scan ./my-repo --tenant-id <uuid> --repository-id <uuid> --history

# Remediate a finding
sem remediate --finding-json '<json>' --approved-by user123
```

## Architecture

```
secret_exposure_monitor/
├── domain/           # Core domain models (Finding, Repository, Secret)
├── ingress/          # Webhooks, broker consumers, schedulers
├── providers/        # GitHub, GitLab, Local Git adapters
├── scanning/         # Pipeline and engines (Gitleaks)
├── classification/   # Secret type detection, confidence scoring
├── remediation/      # Playbooks, revocation, notifications
├── policy/           # Repository scope, actions
├── storage/          # PostgreSQL repositories
├── broker/           # Kafka producer/consumer
└── correlation_contracts/  # Graph-compatible events
```

## Security Model

### Never Store
- Raw secret values
- Full diff content
- Environment dumps

### Always Protect
- HMAC-SHA256 fingerprints with tenant-specific keys
- Redacted previews (e.g., `ghp_****b82a`)
- Scanner runs in isolated container (no network, read-only root)

### Webhook Security
- HMAC signature verification
- Replay protection with delivery ID
- Timestamp window validation
- Rate limiting

## Event Schema

```python
class SecretExposureDetected(BaseModel):
    event_id: UUID
    tenant_id: UUID
    finding_id: UUID
    repository_id: UUID
    commit_sha: str
    secret_fingerprint: str  # HMAC, not raw value
    secret_type: str
    severity: str
    confidence: float
    graph_hints: list[str]  # For Campaign Graph correlation
```

## Remediation Playbook

1. **Revoke** the exposed secret (block at provider)
2. **Rotate** with new credentials
3. **Update** CI/CD and Secret Manager
4. **Delete** from current file
5. **Clean history** (manual approval required)
6. **Notify** affected teams
7. **Resolve** incident after verification

## Configuration

Set environment variables:

```bash
export SEM_TENANT_KEY="<hmac-key-from-vault>"
export SEM_DATABASE_URL="postgresql+asyncpg://..."
export SEM_KAFKA_BROKERS="kafka:9092"
export SEM_GITLEAKS_PATH="/usr/local/bin/gitleaks"
```

## Development

```bash
# Install dev dependencies
pip install -e ".[dev]"

# Run tests
pytest

# Type checking
mypy secret_exposure_monitor

# Linting
ruff check secret_exposure_monitor
black --check secret_exposure_monitor
```

## License

MIT
