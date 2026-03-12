from pydantic import BaseSettings

class Settings(BaseSettings):
    app_name: str = "AI Threat Detection API"
    debug: bool = True

settings = Settings()