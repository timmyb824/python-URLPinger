# type: ignore
import asyncio
import subprocess
from collections.abc import Sequence
from typing import Optional

import aiohttp
import structlog
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from urlpinger.common.db import get_db_context
from urlpinger.common.models import UrlConfig
from urlpinger.config.config import Config
from urlpinger.notifications.send_notifications import send_notification_async

from .metrics import MetricsHandler

logger = structlog.get_logger(__name__)

metrics_handler = MetricsHandler()


async def is_acceptable_status_code(
    code: Optional[int], acceptable_codes: list[int]
) -> bool:
    """
    Check if the status code is acceptable.
    """
    return code in acceptable_codes


async def http_ping(
    config: Config,
) -> tuple[Optional[int], Optional[Exception], Optional[float]]:
    """Perform an HTTP GET request to check the url's status."""
    try:
        timeout = aiohttp.ClientTimeout(total=10)  # TODO: make configurable?
        async with aiohttp.ClientSession() as session:
            start_time = asyncio.get_event_loop().time()
            async with session.get(
                config.url, timeout=timeout, allow_redirects=True
            ) as response:
                response_time = asyncio.get_event_loop().time() - start_time
                return response.status, None, response_time
    except (aiohttp.ClientError, asyncio.TimeoutError) as e:
        logger.exception("HTTP request error", extra={"url": config.url})
        return None, e, None


async def icmp_ping(
    config: Config,
) -> tuple[Optional[int], Optional[Exception], Optional[float]]:
    """Perform an ICMP ping to check the url's status."""
    try:
        start_time = asyncio.get_event_loop().time()
        process = await asyncio.create_subprocess_exec(
            "ping",
            "-c",
            "1",
            "-W",
            "5",
            config.url,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        _, stderr = await process.communicate()
        response_time = asyncio.get_event_loop().time() - start_time
        if process.returncode == 0:
            return 0, None, response_time

        logger.warning("Ping error", extra={"url": config.url})
        return None, Exception(stderr.decode().strip()), None
    except Exception as e:
        logger.exception("Ping error", extra={"url": config.url})
        return None, e, None


async def ping(
    config: Config,
) -> tuple[int | None, Exception | None | str, float | None]:
    """
    Sends either an HTTP GET request or a ping request based on the check_type.
    """
    if config.check_type == "http":
        return await http_ping(config)
    if config.check_type == "ping":
        return await icmp_ping(config)
    return None, Exception(f"Unknown check type: {config.check_type}"), None


async def process_url(
    config: Config,
) -> None:
    """Process a single url."""
    async with get_db_context() as session:
        stmt = select(UrlConfig).where(UrlConfig.url == config.url)
        result = await session.execute(stmt)
        if not (urlconfigs := result.scalars().all()):
            logger.error(
                "Url not found in the database.",
                extra={"url": config.url},
            )
            return

        for urlconfig in urlconfigs:
            # Check if the url is in maintenance mode
            if urlconfig.maintenance:
                logger.info(
                    f"Skipping url {urlconfig.url} due to maintenance mode.",
                    extra={"url": config.url},
                )
                metrics_handler.record_maintenance_mode(
                    urlconfig.url, config.name, config.check_type
                )
                return

            # Continue to check the url if it's not in maintenance mode
            await check_single_url(session, config, urlconfig)


async def check_single_url(
    session: AsyncSession, config: Config, urlconfig: UrlConfig
) -> None:
    """Check a single url and use retries to determine failure status."""
    # If maintenance mode is active, skip the check
    if urlconfig.maintenance:
        logger.info(
            f"Url {config.url} is in maintenance mode. Skipping ping.",
            extra={"url": config.url},
        )
        return

    # Proceed with pinging since maintenance mode is not active
    status_code, error, response_time = await ping(config)
    url, name, type_ = urlconfig.url, config.name, config.check_type

    if error or (
        config.check_type == "http"
        and not await is_acceptable_status_code(
            status_code, config.acceptable_status_codes
        )
    ):
        logger.warning(
            f"{config.name} - Error checking {config.url}",
            extra={"status_code": status_code, "error": str(error)},
        )

        failure_threshold_reached = await handle_failure_retries(session, urlconfig)

        if failure_threshold_reached:
            # Record each failure after the threshold is reached
            metrics_handler.record_check(url, name, type_)
            metrics_handler.record_failure(url, name, type_)

            # Only send the notification the first time the URL goes down
            if (
                urlconfig.status
            ):  # Only send notification if the status is still True (UP)
                urlconfig.status = False
                await session.commit()  # Commit the status change
                logger.info(f"{config.name} - Url {config.url} status updated to DOWN")
                await send_notification_async(f"{config.name} - {config.url} is DOWN!")
        else:
            logger.info(f"{config.name} - Below failure threshold, retrying...")

    else:
        logger.info(f"{config.name} - Url {config.url} is UP")
        metrics_handler.record_check(url, name, type_)
        metrics_handler.record_success(url, name, type_, response_time or 0)

        # Reset failure counter and mark URL as UP if successful
        await reset_failures_and_update_status(session, urlconfig)


async def handle_failure_retries(session: AsyncSession, urlconfig: UrlConfig) -> bool:
    """
    Handles failure retries and checks if the failure threshold has been reached.
    Returns True if the failure threshold is met and False otherwise.
    """
    # Increment consecutive failures
    urlconfig.consecutive_failures = urlconfig.consecutive_failures + 1

    # Check if retries threshold has been reached
    if urlconfig.consecutive_failures >= urlconfig.retries:
        return True  # Threshold reached

    # Commit transient failure count
    await session.commit()
    return False  # Still under the retry limit


async def reset_failures_and_update_status(
    session: AsyncSession, urlconfig: UrlConfig
) -> None:
    """
    Resets the consecutive failure count and updates the URL status to UP if needed.
    """
    urlconfig.consecutive_failures = 0
    if not urlconfig.status:
        # If previously marked as down, mark as up again
        urlconfig.status = True
        logger.info(f"Url {urlconfig.url} status updated to UP")
        await send_notification_async(f"Url {urlconfig.url} is UP!")

    await session.commit()


# without batching
# async def monitor_multiple_urls(configs: Sequence[Config]) -> None:
#     """Monitor multiple urls."""
#     while True:
#         await asyncio.gather(*[process_url(config) for config in configs])
#         await asyncio.sleep(configs[0].check_interval_seconds)


# with batching
async def monitor_multiple_urls(
    configs: Sequence[Config], batch_size: int = 10
) -> None:
    """Monitor multiple urls."""
    while True:
        for i in range(0, len(configs), batch_size):
            batch = configs[i : i + batch_size]
            await asyncio.gather(*[process_url(config) for config in batch])
            await asyncio.sleep(1)
        await asyncio.sleep(configs[0].check_interval_seconds)
