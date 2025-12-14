"""
API Configuration Management

Handles all configuration through environment variables with secure defaults.
"""

import os
from functools import lru_cache
from typing import List

from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    """
    Application settings loaded from environment variables.

    All sensitive values should be stored in environment variables or .env file.
    Never commit secrets to version control.
    """

    # Application Info
    app_name: str = "Defensive Toolkit API"
    app_version: str = "1.2.0"
    app_description: str = "REST API for comprehensive defensive security operations"
    debug: bool = False

    # API Server Configuration
    api_host: str = "0.0.0.0"
    api_port: int = 8000
    api_prefix: str = "/api/v1"

    # Security - JWT Configuration
    secret_key: str = os.getenv(
        "SECRET_KEY",
        "CHANGE_THIS_TO_A_SECURE_RANDOM_KEY_IN_PRODUCTION"
    )
    algorithm: str = "HS256"
    access_token_expire_minutes: int = 15  # Short-lived tokens per 2025 best practices
    refresh_token_expire_days: int = 30

    # Security - API Keys (comma-separated list)
    valid_api_keys: str = os.getenv("VALID_API_KEYS", "")

    # CORS Configuration
    cors_origins: List[str] = [
        "http://localhost:3000",  # React default
        "http://localhost:8080",  # Vue default
        "http://localhost:4200",  # Angular default
    ]
    cors_allow_credentials: bool = True
    cors_allow_methods: List[str] = ["*"]
    cors_allow_headers: List[str] = ["*"]

    # Rate Limiting Configuration
    rate_limit_enabled: bool = True
    rate_limit_default: str = "100/minute"  # Default: 100 requests per minute
    rate_limit_auth: str = "5/minute"  # Login/token refresh: 5 attempts per minute
    rate_limit_heavy: str = "10/minute"  # Heavy operations: 10 per minute

    # Redis Configuration (for distributed rate limiting)
    redis_enabled: bool = False
    redis_host: str = "localhost"
    redis_port: int = 6379
    redis_db: int = 0
    redis_password: str = ""

    # Logging Configuration
    log_level: str = "INFO"
    log_format: str = "json"  # "json" or "text"
    log_file: str = "logs/api.log"

    # Database (if needed for future user management)
    database_url: str = "sqlite:///./defensive_toolkit_api.db"

    # Feature Flags
    enable_swagger_ui: bool = True
    enable_redoc: bool = True
    require_authentication: bool = True

    # File Upload Limits
    max_upload_size_mb: int = 100
    allowed_upload_extensions: List[str] = [
        ".yml", ".yaml", ".yar", ".yara",
        ".json", ".xml", ".log", ".pcap",
        ".evtx", ".csv", ".txt"
    ]

    # Paths
    rules_directory: str = "./rules"
    playbooks_directory: str = "./playbooks"
    logs_directory: str = "./logs"
    temp_directory: str = "./temp"

    class Config:
        """Pydantic configuration"""
        env_file = ".env"
        env_file_encoding = "utf-8"
        case_sensitive = False

    def get_api_keys_list(self) -> List[str]:
        """Parse comma-separated API keys into list"""
        if not self.valid_api_keys:
            return []
        return [key.strip() for key in self.valid_api_keys.split(",") if key.strip()]

    def get_redis_url(self) -> str:
        """Construct Redis connection URL"""
        if not self.redis_enabled:
            return ""

        auth = f":{self.redis_password}@" if self.redis_password else ""
        return f"redis://{auth}{self.redis_host}:{self.redis_port}/{self.redis_db}"

    @property
    def cors_origins_list(self) -> List[str]:
        """
        Get CORS origins as list.
        Allows overriding via CORS_ORIGINS env var (comma-separated).
        """
        env_origins = os.getenv("CORS_ORIGINS")
        if env_origins:
            return [origin.strip() for origin in env_origins.split(",")]
        return self.cors_origins


@lru_cache()
def get_settings() -> Settings:
    """
    Cached settings instance.

    Using lru_cache ensures we only create one Settings instance
    and reuse it for all requests, improving performance.

    Returns:
        Settings: Application configuration
    """
    return Settings()


# Export settings instance for easy import
settings = get_settings()
