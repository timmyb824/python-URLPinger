import asyncio

from sqlalchemy import text
from sqlalchemy.exc import OperationalError

from alembic import command
from alembic.config import Config
from urlpinger.common.db import get_db_context


async def is_database_ready() -> bool:
    """Check if we can connect to the database using an async session."""
    try:
        async with get_db_context() as session:
            await session.execute(text("SELECT 1"))
        return True
    except OperationalError as e:
        print(f"Database not ready: {e}")
        return False


async def check_and_run_migrations():
    """Check if migrations are needed and apply them if necessary."""
    async with get_db_context() as session:
        # Use run_sync to perform a synchronous inspection within an async connection
        async with session.bind.begin() as conn:
            tables_exist = await conn.run_sync(
                lambda conn: bool(conn.dialect.has_table(conn, "url_config"))
            )

        if not tables_exist:
            print("No tables found, applying migrations...")
            alembic_cfg = Config("alembic.ini")
            command.upgrade(alembic_cfg, "head")
        else:
            print("Database is initialized; no migrations needed.")


async def main():
    print("Checking database readiness...")
    retries = 10
    while retries > 0 and not await is_database_ready():
        retries -= 1
        await asyncio.sleep(5)

    if retries == 0:
        print("Database readiness check failed after multiple attempts.")
        return

    await check_and_run_migrations()


if __name__ == "__main__":
    asyncio.run(main())
