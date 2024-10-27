from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager

import structlog
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine
from sqlalchemy.orm import declarative_base, sessionmaker

from urlpinger.common.db_config import settings

logger = structlog.get_logger(__name__)

# Update the SQLALCHEMY_DATABASE_URL to use asyncpg
SQLALCHEMY_DATABASE_URL = (
    f"postgresql+asyncpg://{settings.pg_db_user}:{settings.pg_db_password}"
    f"@{settings.pg_db_host}:{settings.pg_db_port}/{settings.pg_db_name}"
)

# Create async engine
engine = create_async_engine(
    SQLALCHEMY_DATABASE_URL, pool_size=10, max_overflow=20, pool_timeout=30
)

# Create an AsyncSession
AsyncSessionLocal = sessionmaker(  # pyright: ignore
    bind=engine,  # pyright: ignore
    class_=AsyncSession,
    expire_on_commit=False,
    autocommit=False,
    autoflush=False,
)

Base = declarative_base()


@asynccontextmanager
async def get_db_context() -> AsyncGenerator[AsyncSession, None]:
    """Provides an async session for interacting with the database."""
    async with AsyncSessionLocal() as session:  # pyright: ignore
        try:
            logger.debug("Starting database transaction")
            yield session
        except Exception as e:
            await session.rollback()  # Rollback on error
            logger.error("Error during database transaction", exc_info=e)
            raise
        finally:
            logger.debug("Closing database transaction")
            await session.close()
