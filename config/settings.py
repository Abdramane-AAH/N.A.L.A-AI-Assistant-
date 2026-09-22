from pathlib import Path
from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict

BASE_DIR = Path(__file__).resolve().parent.parent

class Settings(BaseSettings):
    # LLM local
    OLLAMA_BASE_URL: str = Field(default="http://127.0.0.1:11434")
    LLM_MODEL_NAME: str = Field(default="llama3.2:3b")

    # Environnement & Logs
    APP_ENV: str = Field(default="development")
    LOG_LEVEL: str = Field(default="INFO")
    
    # Sandbox confinement
    EXECUTION_SANDBOX_PATH: Path = Field(default=BASE_DIR / "workspace")

    # Audio
    STT_MODEL_SIZE: str = Field(default="base")
    TTS_ENGINE: str = Field(default="piper")

    model_config = SettingsConfigDict(
        env_file=str(BASE_DIR / ".env"),
        env_file_encoding="utf-8",
        extra="ignore"
    )

settings = Settings()