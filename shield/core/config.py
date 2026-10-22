"""Global configuration management for AgentShield using pydantic-settings."""

from typing import Dict, Set

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Application settings loaded from environment variables and .env file."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    # Server Settings
    PORT: int = Field(default=8001, description="FastAPI server port")
    HOST: str = Field(default="0.0.0.0", description="FastAPI server host")
    ENVIRONMENT: str = Field(default="development", description="Environment: development, test, production")

    # Security Guardrails Policy
    INJECTION_RISK_THRESHOLD: float = Field(default=0.70, description="Risk threshold for prompt injection detection")
    ENABLE_PII_REDACTION: bool = Field(default=True, description="Enable automatic PII masking")
    ENABLE_TOOL_AUTHORIZATION: bool = Field(default=True, description="Enable tool call pre-execution interceptor")
    ENABLE_OUTPUT_VALIDATION: bool = Field(default=True, description="Enable output filtering and canary check")

    # Request Limitations & DoS Defense
    MAX_TEXT_LENGTH: int = Field(default=50_000, description="Maximum character length for input texts")

    # Destination Control (Allowlist & Blocklist)
    ALLOWED_DESTINATION_DOMAINS: Set[str] = Field(
        default_factory=lambda: {
            "internal.corp",
            "api.github.com",
            "jira.atlassian.net",
            "s3.amazonaws.com",
            "cdn.internal.corp",
            "trusted-cdn.com",
        },
        description="Explicit allowlist of permitted destinations",
    )
    PROHIBITED_DOMAINS: Set[str] = Field(
        default_factory=lambda: {
            "attacker.com",
            "webhook.site",
            "requestbin.com",
            "pipedream.net",
            "ngrok.io",
            "evil.com",
        },
        description="Known malicious or exfiltration hosts",
    )

    # Authentication & Identity Mapping
    REQUIRE_API_KEY: bool = Field(
        default=False,
        description="Require X-API-Key header on all endpoints. If False, allows unauthenticated dev requests with warning.",
    )
    API_KEYS: Dict[str, Dict[str, str]] = Field(
        default_factory=lambda: {
            "admin-key-secret": {
                "user_id": "admin_master",
                "user_role": "admin",
                "tenant_id": "default_tenant",
            },
            "dev-key-secret": {
                "user_id": "developer_1",
                "user_role": "developer",
                "tenant_id": "default_tenant",
            },
            "readonly-key-secret": {
                "user_id": "analyst_1",
                "user_role": "read_only",
                "tenant_id": "default_tenant",
            },
        },
        description="Server-side registry mapping API keys to verified identities",
    )

    # Human Review Approval Gate
    APPROVAL_EXPIRY_SECONDS: int = Field(default=900, description="Expiration time for human approvals in seconds")
    APPROVAL_SECRET: str = Field(
        default="agentshield-super-secret-approval-signing-key-v1",
        description="Key used to sign and verify approval tokens",
    )

    # Benchmark Thresholds
    BENCHMARK_STRICT_MODE: bool = Field(default=True)
    MAX_ALLOWED_FALSE_POSITIVE_RATE: float = Field(default=0.02)
    MAX_ALLOWED_ATTACK_SUCCESS_RATE: float = Field(default=0.05)


# Global singleton instance
settings = Settings()
