import asyncio
import os

import structlog

from urlpinger.common.constants import CONFIG_PATH
from urlpinger.config.config_data import load_and_store_config
from urlpinger.core.pinger import monitor_multiple_urls
from urlpinger.logs.log_handler import configure_logging
from urlpinger.server import app

configure_logging()
logger = structlog.get_logger(__name__)


async def monitor_urls() -> None:
    """
    Start monitoring urls defined in the config file.
    This function will be run in an asyncio task.
    """
    logger.info("Starting endpoint monitoring...")

    # Load endpoint configurations
    configs = await load_and_store_config(CONFIG_PATH)
    if not configs:
        logger.error("No valid configuration found.")
        return

    await monitor_multiple_urls(configs)


async def run_server() -> None:
    """
    Run FastAPI server in a background task.
    Uvicorn's `Config` and `Server` classes allow us to run it in the same event loop.
    """
    import uvicorn

    logger.info("Starting FastAPI health server...")
    config = uvicorn.Config(app, host="0.0.0.0", port=8001, log_level="warning")
    server = uvicorn.Server(config)
    await server.serve()


async def main() -> None:
    """
    Main entry point for the async application.
    It launches both the FastAPI server and the endpoint monitoring task if K8S_ENV is 'prd' or 'local'.
    Otherwise, it only starts the health server.
    """
    app_env = os.environ.get("APP_ENV", "").lower()

    tasks = []

    if app_env in ["prd", "local"]:
        logger.info(
            f"APP_ENV is {app_env}. Starting health server and endpoint monitoring"
        )
        tasks.extend([run_server(), monitor_urls()])  # type: ignore
    else:
        logger.info("APP_ENV is not 'prd' or 'local'. Starting only the health server.")
        tasks.append(run_server())  # type: ignore

    await asyncio.gather(*tasks)


if __name__ == "__main__":
    asyncio.run(main())
