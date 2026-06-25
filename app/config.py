from pydantic_settings import BaseSettings
from functools import lru_cache


class Settings(BaseSettings):
    DATABASE_URL: str = "postgresql://postgres:password@localhost:5432/secure_files_db"
    REDIS_URL: str = "redis://localhost:6379"

    # Azure Blob Storage
    AZURE_CONNECTION_STRING: str = "DefaultEndpointsProtocol=https;AccountName=youraccount;AccountKey=yourkey;EndpointSuffix=core.windows.net"
    AZURE_CONTAINER_NAME: str = "secure-files"

    # AES Master Key (32 bytes base64)
    AES_MASTER_KEY: str = "bXlfc2VjcmV0X2tleV8zMl9ieXRlc19sb25nISE="

    # JWT
    JWT_SECRET: str = "your-super-secret-jwt-key-change-in-production"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 30

    # Key expiry in days
    KEY_EXPIRY_DAYS: int = 90

    ENVIRONMENT: str = "development"

    class Config:
        env_file = ".env"


@lru_cache()
def get_settings() -> Settings:
    return Settings()
