import asyncio
import socket
import ssl
import subprocess
from collections.abc import Sequence
from datetime import datetime, timedelta, timezone
from typing import Optional
from urllib.parse import urlparse

import aiohttp
import structlog
from cryptography.hazmat.backends import default_backend
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from urlpinger.common.db import get_db_context
from urlpinger.common.models import SSLCertificate, UrlConfig
from urlpinger.config.config import Config
from urlpinger.core.metrics import MetricsHandler
from urlpinger.notifications.send_notifications import send_notification_async

logger = structlog.get_logger(__name__)

metrics_handler = MetricsHandler()


def extract_domain(url: str) -> str:
    """Extract the base domain from a URL."""
    hostname = urlparse(url).netloc or url

    # Split hostname into parts
    parts = hostname.split(".")

    # For domains like xxx.local.example.com, return local.example.com
    # For domains like healthchecks.example.com, return example.com
    if len(parts) > 2:
        return ".".join(parts[-3:]) if parts[-3] == "local" else ".".join(parts[-2:])
    return hostname  # return as is for IP addresses or simple domains


async def should_send_ssl_notification(domain: str) -> bool:
    """
    Check if we should send an SSL notification for a domain.
    Only send one notification per domain per day.
    """
    try:
        async with get_db_context() as session:
            ssl_cert = await session.execute(
                select(SSLCertificate).where(SSLCertificate.domain == domain)
            )
            ssl_cert = ssl_cert.scalar_one_or_none()

            if not ssl_cert:
                logger.warning(
                    "ssl_cert_not_found",
                    domain=domain,
                    message="No SSL certificate record found when checking notification status",
                )
                return False

            now = datetime.now(timezone.utc)

            # If we've never sent a notification or it's been more than 24 hours
            should_notify = ssl_cert.last_notification_sent is None or (
                now - ssl_cert.last_notification_sent
            ) > timedelta(days=1)

            if should_notify:
                logger.info(
                    "ssl_notification_needed",
                    domain=domain,
                    days_until_expiry=ssl_cert.days_until_expiry,
                    last_notification=ssl_cert.last_notification_sent,
                )
            else:
                logger.debug(
                    "ssl_notification_skipped",
                    domain=domain,
                    reason="Notification already sent within 24 hours",
                    last_notification=ssl_cert.last_notification_sent,
                )

            return should_notify

    except Exception as e:
        logger.error(
            "ssl_notification_check_error",
            domain=domain,
            error=str(e),
        )
        return False


async def check_ssl_certificate(url: str) -> tuple[Optional[int], Optional[str]]:
    """Check SSL certificate for a given URL."""
    original_hostname = urlparse(url).netloc or url  # Use this for connection
    base_domain = extract_domain(url)  # Use this for storage

    try:
        async with get_db_context() as session:
            try:
                # Check if we already have a recent check for this domain
                ssl_cert = await session.execute(
                    select(SSLCertificate).where(SSLCertificate.domain == base_domain)
                )
                ssl_cert = ssl_cert.scalar_one_or_none()

                now = datetime.now(timezone.utc)
                # If we have a recent check (within last hour), use that
                if (
                    ssl_cert  # type: ignore
                    and ssl_cert.last_checked
                    and (now - ssl_cert.last_checked) < timedelta(hours=1)
                ):
                    logger.debug(
                        "using_cached_ssl_cert",
                        domain=base_domain,
                        url=url,
                        last_checked=ssl_cert.last_checked,
                        days_until_expiry=ssl_cert.days_until_expiry,
                    )
                    return ssl_cert.days_until_expiry, None

                context = ssl.create_default_context()
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE

                with socket.create_connection(
                    (original_hostname, 443), timeout=15
                ) as sock:
                    with context.wrap_socket(
                        sock, server_hostname=original_hostname
                    ) as ssock:
                        cert = ssock.getpeercert(binary_form=True)
                        from cryptography import x509

                        x509_cert = x509.load_der_x509_certificate(
                            cert, default_backend()
                        )
                        expires = x509_cert.not_valid_after.replace(tzinfo=timezone.utc)
                        days_until_expiry = (expires - now).days

                        logger.info(
                            "ssl_cert_checked",
                            domain=base_domain,
                            url=url,
                            expires=expires,
                            days_until_expiry=days_until_expiry,
                        )

                        if ssl_cert:
                            # Update existing record
                            ssl_cert.expiry_date = expires
                            ssl_cert.days_until_expiry = days_until_expiry
                            ssl_cert.last_checked = now
                        else:
                            # Create new record
                            ssl_cert = SSLCertificate(
                                domain=base_domain,
                                expiry_date=expires,
                                days_until_expiry=days_until_expiry,
                                last_checked=now,
                            )
                            session.add(ssl_cert)

                        try:
                            await session.commit()
                            logger.debug(
                                "ssl_cert_db_updated",
                                domain=base_domain,
                                url=url,
                                operation="update" if ssl_cert else "create",
                            )
                        except Exception as db_error:
                            logger.warning(
                                "ssl_db_error",
                                url=url,
                                error=str(db_error),
                                domain=base_domain,
                            )
                            await session.rollback()
                            # Still return the cert info we found
                            return days_until_expiry, None

                        return days_until_expiry, None

            except Exception as db_error:
                if "duplicate key value" in str(db_error):
                    # Log the DB error but don't treat it as an SSL error
                    logger.warning(
                        "ssl_db_duplicate_key",
                        url=url,
                        domain=base_domain,
                    )
                    return None, None
                raise  # Re-raise if it's not a duplicate key error

    except (socket.gaierror, ConnectionRefusedError) as e:
        logger.warning(
            "ssl_connection_error",
            url=url,
            domain=base_domain,
            error=str(e),
        )
        return None, f"Connection error: {str(e)}"
    except ssl.SSLError as e:
        logger.error(
            "ssl_certificate_error",
            url=url,
            domain=base_domain,
            error=str(e),
        )
        return None, f"SSL error: {str(e)}"
    except Exception as e:
        logger.error(
            "ssl_check_failed",
            url=url,
            domain=base_domain,
            error=str(e),
        )
        return None, f"SSL certificate check failed: {str(e)}"


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
        start_time = asyncio.get_event_loop().time()
        async with aiohttp.ClientSession(
            connector=aiohttp.TCPConnector(ssl=False)
        ) as session:  # We handle SSL verification separately
            try:
                async with session.get(
                    config.url,
                    allow_redirects=True,
                    timeout=aiohttp.ClientTimeout(total=15),
                ) as response:
                    response_time = asyncio.get_event_loop().time() - start_time
                    return response.status, None, response_time

            except aiohttp.ClientError as e:
                logger.error("http_request_error", url=config.url, error=str(e))
                return None, e, None

    except Exception as e:
        logger.exception("http_request_error", url=config.url, error=str(e))
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

        logger.warning("ping_error", url=config.url)
        return None, Exception(stderr.decode().strip()), None
    except Exception as e:
        logger.exception("ping_error", url=config.url)
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
                "url_not_found",
                url=config.url,
            )
            return

        for urlconfig in urlconfigs:
            # Check if the url is in maintenance mode
            if urlconfig.maintenance:
                logger.info(
                    "maintenance_mode_enabled",
                    name=config.name,
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
    if urlconfig.maintenance:
        logger.info("maintenance_mode_enabled", name=config.name)
        metrics_handler.record_maintenance_mode(
            config.url, config.name, config.check_type
        )
        return

    # Record that we're checking this endpoint
    metrics_handler.record_check(config.url, config.name, config.check_type)

    # Check SSL certificate if it's an HTTPS URL
    if config.url.startswith("https://"):
        days_until_expiry, ssl_error = await check_ssl_certificate(config.url)
        if ssl_error:
            # Only log the error, don't record metrics for connection/DB issues
            logger.warning("ssl_check_error", url=config.url, error=ssl_error)
            if "SSL error:" in ssl_error:  # Only count actual SSL errors
                metrics_handler.record_ssl_error(
                    config.url, config.name, config.check_type
                )
        elif days_until_expiry is not None and days_until_expiry <= 0:
            # Record expiry by domain for expired certificates
            domain = extract_domain(config.url)
            metrics_handler.ssl_expiry_days.labels(domain=domain, type="https").set(
                days_until_expiry
            )

            if await should_send_ssl_notification(domain):
                days_text = (
                    "today"
                    if days_until_expiry == 0
                    else f"{abs(days_until_expiry)} days ago"
                )
                await send_notification_async(
                    f"SSL Certificate for {domain} has expired {days_text}"
                )
                await update_ssl_notification_time(domain)
        elif days_until_expiry is not None:
            # Record expiry by domain for valid certificates
            domain = extract_domain(config.url)
            metrics_handler.ssl_expiry_days.labels(domain=domain, type="https").set(
                days_until_expiry
            )

    # Use the centralized ping function for all health checks
    status_code, error, response_time = await ping(config)

    if error or (
        config.check_type == "http"
        and not await is_acceptable_status_code(
            status_code, config.acceptable_status_codes
        )
    ):
        logger.warning(
            "check_failed",
            name=config.name,
            url=config.url,
            status_code=status_code,
            error=str(error),
        )

        # Increment consecutive failures and check threshold
        urlconfig.consecutive_failures += 1
        await session.commit()

        if urlconfig.consecutive_failures >= urlconfig.retries:
            metrics_handler.record_failure(config.url, config.name, config.check_type)

            # Only send notification if status is changing from UP to DOWN
            if urlconfig.status:
                urlconfig.status = False
                await session.commit()
                await send_notification_async(f"{config.name} - {config.url} is DOWN!")
        else:
            logger.info(
                "below_failure_threshold",
                name=config.name,
                url=config.url,
                failures=urlconfig.consecutive_failures,
                threshold=urlconfig.retries,
            )
    else:
        logger.info("check_successful", name=config.name, url=config.url)
        metrics_handler.record_success(
            config.url, config.name, config.check_type, response_time or 0
        )

        # Reset failures and update status if needed
        if urlconfig.consecutive_failures > 0 or not urlconfig.status:
            urlconfig.consecutive_failures = 0
            if not urlconfig.status:
                urlconfig.status = True
                await send_notification_async(f"{config.name} - {config.url} is UP!")
            await session.commit()


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
        logger.info("url_status_updated", url=urlconfig.url, status="UP")
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
