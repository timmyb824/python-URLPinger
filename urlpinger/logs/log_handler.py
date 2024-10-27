import json
import logging
import sys
import traceback
from collections import OrderedDict

import structlog


def concise_exc_info(_logger, _log_method, event_dict):
    """Custom processor to reduce verbosity of traceback in logs"""
    if exc_info := event_dict.get("exc_info"):
        # Extract traceback and format it
        if not isinstance(exc_info, tuple):
            # If it's not a tuple, then it's a boolean and we get the current exception
            exc_info = sys.exc_info()
        exc_type, exc_value, exc_traceback = exc_info
        formatted_tb = traceback.format_exception(exc_type, exc_value, exc_traceback)
        # Customize below line to adjust the level of detail needed
        last_line = formatted_tb[-1]
        # Add the last line of traceback to the event dict
        event_dict["exc_info"] = f"Last traceback line: {last_line.strip()}"
    return event_dict


def custom_json_renderer(_, __, event_dict):
    """Custom JSON renderer to ensure 'event' key is always first"""
    reordered_event_dict = OrderedDict()
    if "msg" in event_dict:
        reordered_event_dict["msg"] = event_dict.pop("msg")
    reordered_event_dict.update(event_dict)
    return json.dumps(reordered_event_dict)


def configure_logging():
    # Remove any existing handlers
    root = logging.getLogger()
    if root.handlers:
        for handler in root.handlers:
            root.removeHandler(handler)

    # Define the shared processors
    shared_processors = [
        structlog.stdlib.filter_by_level,
        structlog.stdlib.add_logger_name,
        structlog.stdlib.add_log_level,
        structlog.stdlib.PositionalArgumentsFormatter(),
        structlog.contextvars.merge_contextvars,
        structlog.processors.TimeStamper(fmt="iso"),
        structlog.processors.EventRenamer("msg"),
        concise_exc_info,
        structlog.processors.StackInfoRenderer(),
        structlog.processors.UnicodeDecoder(),
    ]

    # Configure structlog
    structlog.configure(
        processors=shared_processors
        + [
            structlog.stdlib.ProcessorFormatter.wrap_for_formatter,
        ],
        wrapper_class=structlog.stdlib.BoundLogger,
        logger_factory=structlog.stdlib.LoggerFactory(),
        cache_logger_on_first_use=True,
    )

    # Configure standard logging to use structlog
    handler = logging.StreamHandler()
    handler.setFormatter(
        structlog.stdlib.ProcessorFormatter(
            processor=custom_json_renderer,
            foreign_pre_chain=shared_processors,
        )
    )

    root_logger = logging.getLogger()
    root_logger.addHandler(handler)
    root_logger.setLevel(logging.INFO)

    logging.getLogger("werkzeug").disabled = True
    logging.getLogger("apscheduler").setLevel(logging.WARNING)
    logging.getLogger("apprise").setLevel(logging.ERROR)
