# type: ignore
import os

from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    pg_db_host: str = os.environ.get("PG_DB_HOST")
    pg_db_port: str = "5432"
    pg_db_password: str = os.environ.get("PG_DB_PASSWORD")
    pg_db_user: str = os.environ.get("PG_DB_USER")
    pg_db_name: str = os.environ.get("PG_DB_NAME")


settings = Settings()
# type: ignore
