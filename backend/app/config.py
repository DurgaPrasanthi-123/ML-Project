"""Application configuration (12-factor: everything overridable by env)."""

from functools import lru_cache
from pathlib import Path

from pydantic_settings import BaseSettings, SettingsConfigDict

BASE_DIR = Path(__file__).resolve().parent.parent  # backend/


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_prefix="", extra="ignore")

    # --- App identity -----------------------------------------------------
    app_name: str = "Phishing URL Detection API"
    model_version: str = "1.0.0"  # overridden by the trained bundle at load time
    api_version: str = "1.0.0"
    environment: str = "development"

    # --- Model artifacts ----------------------------------------------------
    artifacts_dir: Path = BASE_DIR / "artifacts"
    model_bundle_path: Path = artifacts_dir / "model_bundle.joblib"

    # --- Decision thresholds (frozen; also reported via /model-info) --------
    phishing_threshold: float = 0.75   # P(phish) >= x  -> PHISHING
    suspicious_threshold: float = 0.35  # P(phish) >= x  -> SUSPICIOUS (below -> LEGITIMATE)

    # --- Guardrails (pattern-based safety nets, never URL-specific) ---------
    brand_impersonation_enabled: bool = True
    dns_check_enabled: bool = True
    dns_timeout_seconds: float = 3.0

    # --- Database (scan history) --------------------------------------------
    database_url: str = f"sqlite:///{BASE_DIR / 'artifacts' / 'scan_history.db'}"
    history_enabled: bool = True

    # --- CORS -----------------------------------------------------------------
    cors_origins: list[str] = ["http://localhost:5173", "http://127.0.0.1:5173"]


@lru_cache
def get_settings() -> Settings:
    return Settings()
