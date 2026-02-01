# backend/app/core/config.py

from __future__ import annotations

from typing import List, Optional
from pydantic_settings import BaseSettings, SettingsConfigDict
from pydantic import Field


class Settings(BaseSettings):
    """
    Pydantic Settings v2
    - extra="allow": prevents crash when .env contains keys not declared here
    - case_sensitive=False: allows different casing in env vars
    """

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="allow",
        case_sensitive=False,
    )

    # -------------------------
    # General
    # -------------------------
    DEBUG: bool = Field(default=False)
    ENVIRONMENT: str = Field(default="production")
    TIMEZONE: str = Field(default="Africa/Johannesburg")

    # -------------------------
    # CORS
    # -------------------------
    # Comma-separated origins, e.g.
    # CORS_ORIGINS=https://frontend-038v.onrender.com,http://localhost:5173
    CORS_ORIGINS: str = Field(
        default=(
            "http://localhost:5173,http://127.0.0.1:5173,"
            "http://localhost:3000,http://127.0.0.1:3000,"
            "http://localhost:3002,http://127.0.0.1:3002"
        )
    )

    # Frontend public URL (Render static site)
    FRONTEND_URL: str = Field(default="http://localhost:5173")

    # -------------------------
    # Uploads
    # -------------------------
    MAX_UPLOAD_SIZE_MB: int = Field(default=50)
    UPLOAD_DIR: str = Field(default="./uploads")

    # -------------------------
    # Sunsynk API (DO NOT hardcode secrets in production)
    # -------------------------
    SUNSYNK_API_URL: str = Field(default="https://openapi.sunsynk.net")
    SUNSYNK_API_KEY: str = Field(default="")
    SUNSYNK_API_SECRET: str = Field(default="")

    # -------------------------
    # Mongo (support many historic names)
    # -------------------------
    MONGODB_URL: Optional[str] = Field(default=None)
    MONGODB_URI: Optional[str] = Field(default=None)
    MONGO_URI: Optional[str] = Field(default=None)

    MONGO_DB_NAME: Optional[str] = Field(default=None)
    MONGODB_DB: Optional[str] = Field(default=None)

    # -------------------------
    # Redis
    # -------------------------
    REDIS_URL: Optional[str] = Field(default=None)

    # -------------------------
    # Gemini AI (DO NOT hardcode in production)
    # -------------------------
    GEMINI_API_KEY: str = Field(default="")
    GEMINI_MODEL_ESG: str = Field(default="gemini-1.5-flash")

    # -------------------------
    # JWT Authentication (DO NOT hardcode SECRET_KEY in production)
    # -------------------------
    ACCESS_TOKEN_EXPIRE_MINUTES: int = Field(default=30)
    SECRET_KEY: str = Field(default="CHANGE_ME_IN_RENDER_ENV")
    ALGORITHM: str = Field(default="HS256")
    AUTH_ENABLED: bool = Field(default=True)

    # -------------------------
    # Email Configuration (DO NOT hardcode in production)
    # -------------------------
    EMAIL_HOST: str = Field(default="smtp.gmail.com")
    EMAIL_PORT: int = Field(default=587)
    EMAIL_USERNAME: str = Field(default="")
    EMAIL_PASSWORD: str = Field(default="")
    EMAIL_FROM: str = Field(default="noreply@africaesg.ai")
    EMAIL_FROM_NAME: str = Field(default="AfricaESG.AI")

    # -------------------------
    # Carbon Emissions Calculation
    # -------------------------
    CARBON_FACTOR_KG_PER_KWH: float = Field(default=0.93)

    # -------------------------
    # Portfolio / Asset naming
    # -------------------------
    DUBE_TRADE_PORT_PORTFOLIO_NAME: str = Field(default="Dube Trade Port")
    BERTHA_HOUSE_ASSET_NAME: str = Field(default="Bertha House")
    BERTHA_HOUSE_METER_NAME: str = Field(default="Local Mains")

    # -------------------------
    # eGauge
    # -------------------------
    EGAUGE_BASE_URL: str = Field(default="")  # keep empty if not used
    EGAUGE_USERNAME: Optional[str] = Field(default=None)
    EGAUGE_PASSWORD: Optional[str] = Field(default=None)
    EGAUGE_POLL_INTERVAL_SECONDS: int = Field(default=60)
    BERTHA_HOUSE_COST_PER_KWH: float = Field(default=2.00)

    # -------------------------
    # Helpers
    # -------------------------
    def get_cors_origins(self) -> List[str]:
        return [o.strip() for o in (self.CORS_ORIGINS or "").split(",") if o.strip()]

    def get_mongo_uri(self) -> str:
        return (
            self.MONGODB_URL
            or self.MONGODB_URI
            or self.MONGO_URI
            or "mongodb://localhost:27017"
        )

    def get_mongo_db(self) -> str:
        return self.MONGO_DB_NAME or self.MONGODB_DB or "esg_dashboard"


settings = Settings()
