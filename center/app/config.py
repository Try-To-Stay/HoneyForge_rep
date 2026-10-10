"""Application settings, loaded from environment (see .env.example)."""
from __future__ import annotations

from functools import lru_cache

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    # PostgreSQL
    postgres_user: str = "honeyforge"
    postgres_password: str = "change-me"
    postgres_db: str = "honeyforge"
    postgres_host: str = "postgres"
    postgres_port: int = 5432
    database_url: str | None = None

    # Redis
    redis_host: str = "redis"
    redis_port: int = 6379
    redis_url: str | None = None

    # Auth (used from Sprint 1 onward)
    jwt_secret: str = "dev-only-change-me"
    jwt_access_ttl_min: int = 30
    jwt_refresh_ttl_days: int = 7

    # Honeypot liveness
    honeypot_offline_ttl_s: int = 120

    @property
    def sqlalchemy_url(self) -> str:
        if self.database_url:
            return self.database_url
        return (
            f"postgresql+asyncpg://{self.postgres_user}:{self.postgres_password}"
            f"@{self.postgres_host}:{self.postgres_port}/{self.postgres_db}"
        )

    @property
    def redis_dsn(self) -> str:
        if self.redis_url:
            return self.redis_url
        return f"redis://{self.redis_host}:{self.redis_port}/0"


@lru_cache
def get_settings() -> Settings:
    return Settings()
