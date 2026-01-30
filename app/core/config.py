# backend/app/core/config.py

from __future__ import annotations

from typing import List, Optional
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """
    Pydantic Settings v2
    - ✅ extra="allow": prevents crash when .env contains keys not declared here
    - ✅ supports multiple env var names (mongo_uri / mongodb_uri / MONGODB_URI / etc.)
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
    DEBUG: bool = True
    ENVIRONMENT: str = "development"
    TIMEZONE: str = "Africa/Johannesburg"

    # -------------------------
    # CORS
    # -------------------------
    CORS_ORIGINS: str = (
        "http://localhost:3001,http://localhost:3002,http://localhost:3008,http://localhost:5173,"
        "http://127.0.0.1:3001,http://127.0.0.1:3002,http://127.0.0.1:3008,http://127.0.0.1:5173"
    )

    # -------------------------
    # Uploads
    # -------------------------
    MAX_UPLOAD_SIZE_MB: int = 50
    UPLOAD_DIR: str = "./uploads"

    # -------------------------
    # Sunsynk API
    # -------------------------
    SUNSYNK_API_URL: str = "https://openapi.sunsynk.net"
    SUNSYNK_API_KEY: str = "204013305"
    SUNSYNK_API_SECRET: str = "zIQJeoPRXCjDV5anS5WIH7SQPAgdVaPm"

    # -------------------------
    # Mongo (support many historic names)
    # -------------------------
    MONGODB_URL: Optional[str] = None
    MONGODB_URI: Optional[str] = None
    MONGO_URI: Optional[str] = None

    MONGO_DB_NAME: Optional[str] = None
    MONGODB_DB: Optional[str] = None

    # -------------------------
    # Redis
    # -------------------------
    REDIS_URL: Optional[str] = None

    # ===== Gemini AI =====
    GEMINI_API_KEY: str = "AIzaSyAfvt0OQDMbF0aJEr4qjH0bvBocQagQ2Rg"
    GEMINI_MODEL_ESG: str = "gemini-1.5-flash"

    # -------------------------
    # JWT Authentication
    # -------------------------
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 30
    SECRET_KEY: str = "your-secret-key-change-in-production"
    ALGORITHM: str = "HS256"
    AUTH_ENABLED: bool = True

    # -------------------------
    # Email Configuration
    # -------------------------
    EMAIL_HOST: str = "smtp.gmail.com"
    EMAIL_PORT: int = 587
    EMAIL_USERNAME: str = "your-email@gmail.com"
    EMAIL_PASSWORD: str = "your-app-password"
    EMAIL_FROM: str = "noreply@africaesg.ai"
    EMAIL_FROM_NAME: str = "AfricaESG.AI"
    FRONTEND_URL: str = "http://localhost:5173"

    # -------------------------
    # Carbon Emissions Calculation
    # -------------------------
    # Formula: tCO₂e = kWh × 0.93 ÷ 1000
    # This means 0.93 kgCO₂e per kWh
    CARBON_FACTOR_KG_PER_KWH: float = 0.93

    # -------------------------
    # Portfolio / Asset naming
    # -------------------------
    DUBE_TRADE_PORT_PORTFOLIO_NAME: str = "Dube Trade Port"
    BERTHA_HOUSE_ASSET_NAME: str = "Bertha House"
    BERTHA_HOUSE_METER_NAME: str = "Local Mains"

    # -------------------------
    # eGauge
    # -------------------------
    EGAUGE_BASE_URL: str = "https://egauge65730.egaug.es/63C1A1"  # Added device path
    EGAUGE_USERNAME: Optional[str] = "bertha"
    EGAUGE_PASSWORD: Optional[str] = "bertha@house.2023"
    EGAUGE_POLL_INTERVAL_SECONDS: int = 60
    BERTHA_HOUSE_COST_PER_KWH: float = 2.00

    # -------------------------
    # Helpers
    # -------------------------
    def get_cors_origins(self) -> List[str]:
        return [o.strip() for o in self.CORS_ORIGINS.split(",") if o.strip()]

    def get_mongo_uri(self) -> str:
        # Prefer explicit values, fall back to localhost if nothing set
        return (
            self.MONGODB_URL
            or self.MONGODB_URI
            or self.MONGO_URI
            or "mongodb://localhost:27017"
        )

    def get_mongo_db(self) -> str:
        return self.MONGO_DB_NAME or self.MONGODB_DB or "esg_dashboard"


settings = Settings()