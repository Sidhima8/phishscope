import os
from typing import List, Optional
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    PROJECT_NAME: str = "PhishScope"
    VERSION: str = "1.0.0"
    API_V1_STR: str = "/api/v1"
    
    # Security
    SECRET_KEY: str = "phishscope-production-grade-soc-analyst-secret-key-32b-min"
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 60 * 24  # 24 hours
    
    # Database (Default to aiosqlite for zero-config local run, supports Postgres via env)
    DATABASE_URL: str = "sqlite+aiosqlite:///./phishscope.db"
    
    # Threat Intelligence Integrations (Keys read from environment, fallback to unconfigured status)
    VIRUSTOTAL_API_KEY: Optional[str] = None
    URLHAUS_API_KEY: Optional[str] = None
    GEMINI_API_KEY: Optional[str] = None
    
    # Operational limits & security
    MAX_UPLOAD_SIZE_MB: int = 25
    SSRF_TIMEOUT_SECONDS: float = 4.0
    MAX_REDIRECT_HOPS: int = 5
    ALLOW_ORIGINS: List[str] = [
        "http://localhost:5173",
        "http://127.0.0.1:5173",
        "http://localhost:3000",
        "http://localhost:8000",
        "http://127.0.0.1:8000"
    ]

    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")


settings = Settings()
