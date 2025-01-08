import asyncio
import os
import threading
from concurrent.futures import ThreadPoolExecutor

import apprise
import structlog

logger = structlog.get_logger(__name__)

# Create a singleton Apprise instance and lock
_apprise_instance = None
_apprise_lock = threading.Lock()


def get_apprise_instance():
    """Get or create the singleton Apprise instance."""
    global _apprise_instance

    # Use a lock to prevent race conditions during initialization
    with _apprise_lock:
        if _apprise_instance is None:
            _apprise_instance = apprise.Apprise()
            services_added = False

            # Add all services from environment variables
            for key, value in os.environ.items():
                if key.startswith("APPRISE_"):
                    logger.info("Adding notification service", extra={"key": key})
                    _apprise_instance.add(value)
                    services_added = True

            if not services_added:
                logger.warning(
                    "No notification services configured in environment variables"
                )

        return _apprise_instance


async def send_notification_async(message: str) -> None:
    """Send notification asynchronously using Apprise with environment variables."""

    def notify_sync():
        try:
            apobj = get_apprise_instance()
            if not apobj.servers:
                logger.warning(
                    "No notification services available, skipping notification"
                )
                return

            logger.info("Sending notification")
            success = apobj.notify(body=message, title="URL Pinger Notification")
            if success:
                logger.info("Notification sent successfully")
            else:
                logger.error("Failed to send notification")
        except Exception as e:
            logger.exception("Error sending notification", exc_info=e)

    loop = asyncio.get_running_loop()
    # Run the synchronous notification function in a separate thread
    await loop.run_in_executor(ThreadPoolExecutor(), notify_sync)
