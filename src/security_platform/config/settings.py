import os
from pathlib import Path

from pydantic import BaseModel, Field, SecretStr, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class DatabaseSettings(BaseModel):
    url: str = Field(default="sqlite:///secorchestrator.db", description="Database connection URL")
    pool_size: int = Field(default=10, ge=1, le=100)
    max_overflow: int = Field(default=20, ge=0)
    echo: bool = False


class RedisSettings(BaseModel):
    url: str = Field(default="redis://localhost:6379/0", description="Redis connection URL")
    queue_name: str = Field(default="secorch_scans")


class SecuritySettings(BaseModel):
    jwt_secret: SecretStr | None = None
    jwt_algorithm: str = "HS256"
    jwt_expiry_seconds: int = 3600
    webhook_secret: SecretStr | None = None
    allowed_scan_roots: list[str] = Field(default_factory=lambda: ["/tmp"])


class ObservabilitySettings(BaseModel):
    environment: str = Field(default="development")
    log_level: str = Field(default="INFO")
    prometheus_enabled: bool = True
    otel_exporter_endpoint: str | None = None


_configured_secrets_dir = os.getenv("SEC_ORCH_SECRETS_DIR", "/var/run/secrets/secorch")
_secrets_dir_exists = Path(_configured_secrets_dir).exists()


class PlatformSettings(BaseSettings):
    """Central configuration management for SecOrchestrator powered by pydantic-settings."""

    model_config = SettingsConfigDict(
        env_prefix="SEC_ORCH_",
        env_nested_delimiter="__",
        secrets_dir=_configured_secrets_dir if _secrets_dir_exists else None,
        extra="ignore",
    )

    environment: str = Field(default="development")
    database: DatabaseSettings = Field(default_factory=DatabaseSettings)
    redis: RedisSettings = Field(default_factory=RedisSettings)
    security: SecuritySettings = Field(default_factory=SecuritySettings)
    observability: ObservabilitySettings = Field(default_factory=ObservabilitySettings)

    @field_validator("environment")
    @classmethod
    def validate_environment(cls, v: str) -> str:
        allowed = {"development", "staging", "production", "test"}
        if v.lower() not in allowed:
            raise ValueError(f"Environment must be one of {allowed}")
        return v.lower()

    def get_jwt_secret_value(self) -> str:
        """Retrieves verified JWT secret, enforcing strict presence in production."""
        if self.security.jwt_secret:
            return self.security.jwt_secret.get_secret_value()

        if self.environment == "production":
            raise ValueError(
                "CRITICAL: SEC_ORCH_SECURITY__JWT_SECRET must be provided in production via Vault, "
                "AWS Secrets Manager, or Kubernetes Secret volume. Fallback defaults are strictly forbidden."
            )

        # Non-production fallback only
        return "secorch_dev_only_insecure_secret_at_least_32_bytes_long"


def load_settings(secrets_dir: Path | str | None = None) -> PlatformSettings:
    """Loads platform settings with optional override directory for mounted secrets."""
    if secrets_dir:
        return PlatformSettings(_secrets_dir=str(secrets_dir))  # type: ignore[call-arg]
    return PlatformSettings()
