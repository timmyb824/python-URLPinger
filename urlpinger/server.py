from typing import Literal

import structlog
from fastapi import FastAPI
from prometheus_client import CONTENT_TYPE_LATEST, generate_latest
from starlette.responses import Response

logger = structlog.get_logger(__name__)

app = FastAPI()

is_healthy = True


@app.get("/health")
async def health_check() -> dict[str, str] | tuple[dict[str, str], Literal[503]]:
    """
    Basic health check endpoint.
    Returns 200 if the app is healthy.
    """
    return {"status": "ok"} if is_healthy else ({"status": "error"}, 503)


@app.get("/metrics")
async def metrics() -> Response:
    """Serve Prometheus metrics"""
    return Response(generate_latest(), media_type=CONTENT_TYPE_LATEST)
