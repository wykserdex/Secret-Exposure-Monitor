"""Secret domain models and utilities."""

import hashlib
import hmac
from typing import Literal


def secret_fingerprint(
    secret: bytes,
    *,
    tenant_key: bytes,
    key_version: str = "v1",
) -> str:
    """Generate HMAC-SHA256 fingerprint for a secret.
    
    Args:
        secret: The raw secret value (will not be stored).
        tenant_key: Tenant-specific HMAC key from Vault/KMS.
        key_version: Version identifier for key rotation support.
    
    Returns:
        Fingerprint in format "{key_version}:{hex_digest}".
    
    Security:
        After calling this function, the raw secret should be
        immediately cleared from memory.
    """
    digest = hmac.new(tenant_key, secret, hashlib.sha256).hexdigest()
    return f"{key_version}:{digest}"


def redact_secret(value: str, visible_chars: int = 4) -> str:
    """Create a safe redacted preview of a secret.
    
    Args:
        value: The secret value.
        visible_chars: Number of characters to show at start/end.
    
    Returns:
        Redacted string like "ghp_****b82a" or "[REDACTED]" for short values.
    """
    if len(value) < visible_chars * 2 + 2:
        return "[REDACTED]"
    
    return f"{value[:visible_chars]}…{value[-visible_chars:]}"


class SecretType:
    """Known secret types for classification."""

    GITHUB_PAT = "github_personal_access_token"
    GITHUB_OAUTH = "github_oauth_token"
    GITLAB_PAT = "gitlab_personal_access_token"
    AWS_ACCESS_KEY = "aws_access_key_id"
    AWS_SECRET_KEY = "aws_secret_access_key"
    SLACK_BOT_TOKEN = "slack_bot_token"
    STRIPE_API_KEY = "stripe_api_key"
    GENERIC_HIGH_ENTROPY = "generic_high_entropy_string"
