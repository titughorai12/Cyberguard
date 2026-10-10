import json
from typing import List

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    # Application settings
    PROJECT_NAME: str = "CyberGuard XAI Engine"
    API_V1_STR: str = "/api/v1"

    # PostgreSQL database
    DATABASE_URL: str = (
        "postgresql+psycopg://postgres:CHANGE_ME@localhost:5432/cyberguard"
    )

    # Gemini AI configuration
    GEMINI_API_KEY: str = ""
    GEMINI_MODEL: str = "gemini-2.5-flash"

    # Existing Supabase configuration
    SUPABASE_URL: str = "https://mock.supabase.co"
    SUPABASE_ANON_KEY: str = "mock_anon_key"
    SUPABASE_SERVICE_ROLE_KEY: str = "mock_service_role"
    SUPABASE_JWT_SECRET: str = (
        "super-secret-jwt-token-key-for-development"
    )

    # API security
    BACKEND_API_KEY: str = "cyberguard_secret_api_key_2026_dev"

    # Rate limiting
    RATE_LIMIT_PER_MINUTE: int = 30
    PUBLIC_DEMO_MODE: bool = False

    # Existing AI configuration
    MODEL_PROVIDER: str = "gemini"

    # CORS settings
    BACKEND_CORS_ORIGINS: List[str] = Field(default_factory=list)

    @field_validator("BACKEND_CORS_ORIGINS", mode="before")
    @classmethod
    def parse_cors_origins(cls, value):
        if isinstance(value, str):
            value = value.strip()

            if value.startswith("["):
                return json.loads(value)

            return [
                origin.strip()
                for origin in value.split(",")
                if origin.strip()
            ]

        return value

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=True,
        extra="ignore",
    )


settings = Settings()
