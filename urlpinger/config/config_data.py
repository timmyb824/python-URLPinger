import json

import structlog
from sqlalchemy import select
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncSession

from urlpinger.common.db import get_db_context
from urlpinger.common.models import UrlConfig
from urlpinger.config.config import Config

logger = structlog.get_logger(__name__)

DEFAULT_ACCEPTABLE_STATUS_CODES = [200]
DEFAULT_RETRIES = 0
DEFAULT_RETRY_INTERVAL_SECONDS = 5
DEFAULT_CONSECUTIVE_FAILURES = 0
DEFAULT_CHECK_INTERVAL = 120
DEFAULT_CHECK_TYPE = "http"
DEFAULT_MAINTENANCE = False
DEFAULT_STATUS = True


async def store_config_to_db(configs: list[Config]) -> None:
    """
    Stores the list of Config objects in the database asynchronously.
    """
    data = [config.__dict__ for config in configs]
    logger.info(f"Storing {len(data)} configurations to the database.")

    async with get_db_context() as db:
        try:
            for config_data in data:
                await upsert_config(db, config_data)

            await db.commit()
            logger.info("Configurations successfully stored in the database.")

        except SQLAlchemyError as e:
            logger.error("Error storing configurations to the database.", exc_info=e)
            await db.rollback()


async def upsert_config(db: AsyncSession, config_data: dict) -> None:
    """
    Updates an existing config or inserts a new one if it does not exist.
    """
    existing_config_query = (
        select(UrlConfig)
        .where(
            UrlConfig.url == config_data["url"],
            UrlConfig.name == config_data["name"],
            UrlConfig.check_type == config_data["check_type"],
        )
        .limit(1)
    )

    existing_config = await db.execute(existing_config_query)
    if config_instance := existing_config.scalar_one_or_none():
        logger.info(
            "Updating existing configuration in the database.",
            name=config_data["name"],
            url=config_data["url"],
            maintenance=config_data.get("maintenance", DEFAULT_MAINTENANCE),  # type: ignore
        )
        config_instance.acceptable_status_codes = config_data.get(  # type: ignore
            "acceptable_status_codes"
        )
        config_instance.retries = config_data.get("retries")  # type: ignore
        config_instance.retry_interval_seconds = config_data.get(
            "retry_interval_seconds", DEFAULT_RETRY_INTERVAL_SECONDS
        )
        config_instance.check_interval_seconds = config_data.get(  # type: ignore
            "check_interval_seconds"
        )
        config_instance.check_type = config_data.get("check_type")  # type: ignore
        config_instance.maintenance = config_data.get(  # type: ignore
            "maintenance", DEFAULT_MAINTENANCE
        )
    else:
        logger.info(
            "Adding new configuration to the database.",
            name=config_data["name"],
            url=config_data["url"],
        )
        new_config = UrlConfig(**config_data)
        db.add(new_config)


def load_config(filename: str) -> list[Config]:
    """
    Reads configuration from a JSON file and provides defaults for missing fields.
    Returns a list of Config objects.
    """
    try:
        with open(filename, "r", encoding="utf-8") as f:
            config_data = json.load(f)

        urls = config_data.get("urls", [])
        return [
            Config(
                name=urldata.get("name", "Unnamed url"),
                url=urldata.get("url"),
                acceptable_status_codes=urldata.get(
                    "acceptable_status_codes", DEFAULT_ACCEPTABLE_STATUS_CODES
                ),
                retries=urldata.get("retries", DEFAULT_RETRIES),
                retry_interval_seconds=urldata.get(
                    "retry_interval_seconds", DEFAULT_RETRY_INTERVAL_SECONDS
                ),
                consecutive_failures=urldata.get(
                    "consecutive_failures", DEFAULT_CONSECUTIVE_FAILURES
                ),
                check_interval_seconds=urldata.get(
                    "check_interval_seconds", DEFAULT_CHECK_INTERVAL
                ),
                check_type=urldata.get("check_type", DEFAULT_CHECK_TYPE),
                maintenance=urldata.get("maintenance", DEFAULT_MAINTENANCE),
                status=urldata.get("status", DEFAULT_STATUS),
            )
            for urldata in urls
        ]

    except (IOError, json.JSONDecodeError) as e:
        logger.error(f"Error loading configuration from {filename}: {e}")
        return []


async def load_and_store_config(filename: str) -> list[Config]:
    """
    Reads configuration from a JSON file and stores it in the database asynchronously.
    """
    if configs := load_config(filename):
        await store_config_to_db(configs)

    return configs
