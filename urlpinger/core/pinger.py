import asyncio
import socket
import ssl
from collections.abc import Sequence
from datetime import datetime, timedelta, timezone
from typing import Optional, Tuple
from urllib.parse import urlparse

import aiohttp
import structlog
from icmplib import ICMPLibError, async_ping
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from urlpinger.common.db import get_db_context
from urlpinger.common.models import SSLCertificate, UrlConfig
from urlpinger.config.config import Config
from urlpinger.core.metrics import MetricsHandler
from urlpinger.notifications.send_notifications import send_notification_async

logger = structlog.get_logger(__name__)

# Global metrics handler instance
metrics_handler = MetricsHandler()


def extract_domain(url: str) -> str:
    """Extract the base domain from a URL."""
    hostname = urlparse(url).netloc or url

    # Split hostname into parts
    parts = hostname.split(".")

    # For domains like xxx.local.timmybtech.com, return local.timmybtech.com
    # For domains like healthchecks.timmybtech.com, return timmybtech.com
    if len(parts) > 2:
        return ".".join(parts[-3:]) if parts[-3] == "local" else ".".join(parts[-2:])
    return hostname  # return as is for IP addresses or simple domains


async def should_send_ssl_notification(url: str) -> bool:
    """Check if we should send an SSL notification for this domain.
    Limits notifications to once per 24 hours per domain."""
    try:
        base_domain = extract_domain(url)
        now = datetime.now(timezone.utc)

        async with get_db_context() as session:
            ssl_cert = await session.execute(
                select(SSLCertificate).where(SSLCertificate.domain == base_domain)
            )
            if ssl_cert := ssl_cert.scalar_one_or_none():
                if ssl_cert.last_notification_sent is None:
                    ssl_cert.last_notification_sent = now
                    await session.commit()
                    return True

                # Check if 24 hours have passed since last notification
                if (now - ssl_cert.last_notification_sent) > timedelta(hours=24):
                    ssl_cert.last_notification_sent = now
                    await session.commit()
                    return True

                return False

            # No record found, should send notification
            return True

    except Exception as e:
        logger.error("ssl_notification_check_error", error=str(e))
        # If there's an error, we'll allow the notification to be sent
        return True


async def check_ssl_certificate(url: str) -> Tuple[Optional[int], Optional[str]]:
    """Check SSL certificate for a given URL."""
    original_hostname = urlparse(url).netloc or url  # Use this for connection
    base_domain = extract_domain(url)  # Use this for storage

    try:
        async with get_db_context() as session:
            # Check if we already have a recent check for this domain
            ssl_cert = await session.execute(
                select(SSLCertificate).where(SSLCertificate.domain == base_domain)
            )
            ssl_cert = ssl_cert.scalar_one_or_none()

            now = datetime.now(timezone.utc)
            # If we have a recent check (within last hour), use that
            if (
                ssl_cert
                and ssl_cert.last_checked
                and (now - ssl_cert.last_checked) < timedelta(hours=1)
            ):
                metrics_handler.ssl_expiry_days.labels(
                    domain=base_domain, type="https"
                ).set(ssl_cert.days_until_expiry)
                return ssl_cert.days_until_expiry, None

            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE

            with socket.create_connection((original_hostname, 443), timeout=10) as sock:
                with context.wrap_socket(
                    sock, server_hostname=original_hostname
                ) as ssock:
                    cert = ssock.getpeercert(binary_form=True)
                    from cryptography import x509
                    from cryptography.hazmat.backends import default_backend

                    x509 = x509.load_der_x509_certificate(cert, default_backend())
                    expires = x509.not_valid_after.replace(tzinfo=timezone.utc)
                    days_until_expiry = (expires - now).days

                    # Update or create SSL certificate record
                    if ssl_cert:
                        ssl_cert.expiry_date = expires
                        ssl_cert.days_until_expiry = days_until_expiry
                        ssl_cert.last_checked = now
                    else:
                        ssl_cert = SSLCertificate(
                            domain=base_domain,
                            expiry_date=expires,
                            days_until_expiry=days_until_expiry,
                            last_checked=now,
                        )
                        session.add(ssl_cert)

                    await session.commit()
                    metrics_handler.ssl_expiry_days.labels(
                        domain=base_domain, type="https"
                    ).set(days_until_expiry)
                    return days_until_expiry, None

    except (socket.gaierror, ConnectionRefusedError) as e:
        return None, f"Connection error: {str(e)}"
    except ssl.SSLError as e:
        return None, f"SSL error: {str(e)}"
    except Exception as e:
        return None, f"Error checking SSL certificate: {str(e)}"


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
                    timeout=aiohttp.ClientTimeout(total=10),
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
        process = await async_ping(config.url, count=1, interval=1, timeout=5)
        response_time = asyncio.get_event_loop().time() - start_time
        if process.is_alive:
            return 0, None, response_time

        logger.warning("ping_error", url=config.url)
        return None, Exception("Ping failed"), None
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
            logger.error("ssl_check_error", url=config.url, error=ssl_error)
            metrics_handler.record_ssl_error(config.url, config.name, config.check_type)
            if await should_send_ssl_notification(config.url):
                await send_notification_async(
                    f"SSL Certificate error for {extract_domain(config.url)}: {ssl_error}"
                )
        elif days_until_expiry is not None and days_until_expiry <= 0:
            metrics_handler.record_ssl_error(config.url, config.name, config.check_type)
            if await should_send_ssl_notification(config.url):
                domain = extract_domain(config.url)
                days_text = (
                    "today"
                    if days_until_expiry == 0
                    else f"{abs(days_until_expiry)} days ago"
                )
                await send_notification_async(
                    f"SSL Certificate for {domain} has expired {days_text}"
                )

    # Perform the actual health check
    status_code = None
    error = None
    for attempt in range(config.retries + 1):
        if config.check_type == "http":
            status_code, error, response_time = await http_ping(config)
        else:  # ping
            try:
                status_code, error, response_time = await icmp_ping(config)
            except ICMPLibError as e:
                if "Root privileges are required" not in str(e):
                    raise

                logger.warning("ping_requires_root_privileges", url=config.url)
                # Fall back to HTTP ping if we don't have root privileges
                status_code, error, response_time = await http_ping(config)
        if await is_acceptable_status_code(status_code, config.acceptable_status_codes):
            if urlconfig.consecutive_failures > 0:
                logger.info(
                    "service_recovered",
                    name=config.name,
                    failures=urlconfig.consecutive_failures,
                )
                urlconfig.consecutive_failures = 0
                await session.commit()
            logger.info("url_check_success", name=config.name, url=config.url)
            metrics_handler.record_success(
                config.url, config.name, config.check_type, response_time
            )
            return

        if attempt < config.retries:
            logger.info("retry_attempt", name=config.name)
            await asyncio.sleep(config.retry_interval_seconds)

    # All retries failed
    urlconfig.consecutive_failures += 1
    await session.commit()

    error_msg = str(error) if error else ""
    logger.warning(
        "url_check_error",
        name=config.name,
        url=config.url,
        status_code=status_code,
        error=error_msg,
    )
    metrics_handler.record_failure(config.url, config.name, config.check_type)


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
