from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    # Default free hosted target model
    groq_api_key: str = ""
    default_model_name: str = "llama-3.1-8b-instant"
    default_provider: str = "groq"
    groq_base_url: str = "https://api.groq.com/openai/v1"

    frontend_origin: str = "http://localhost:5173"
    database_url: str = "sqlite:///./sentinel.db"

    # Runner tuning
    run_concurrency: int = 5
    request_timeout_s: float = 30.0


settings = Settings()
