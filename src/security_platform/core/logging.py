"""Structured logging configuration for SecOrchestrator."""

import json
import logging
import sys
from datetime import UTC, datetime
from typing import Any


class JSONFormatter(logging.Formatter):
    """Formats log records as structured single-line JSON objects."""

    def format(self, record: logging.LogRecord) -> str:
        log_entry: dict[str, Any] = {
            "timestamp": datetime.now(UTC).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }

        # Include extra context attributes if provided
        for key, value in record.__dict__.items():
            if key not in {
                "name", "msg", "args", "levelname", "levelno", "pathname", "filename",
                "module", "exc_info", "exc_text", "stack_info", "lineno", "funcName",
                "created", "msecs", "relativeCreated", "thread", "threadName",
                "processName", "process", "message"
            } and not key.startswith("_"):
                log_entry[key] = value

        if record.exc_info:
            log_entry["exception"] = self.formatException(record.exc_info)

        return json.dumps(log_entry)


def setup_logging(level: int = logging.INFO, json_output: bool = True) -> logging.Logger:
    """Configures root logger with structured JSON or human-readable format."""
    logger = logging.getLogger("security_platform")
    logger.setLevel(level)

    # Avoid duplicate handlers
    if not logger.handlers:
        handler = logging.StreamHandler(sys.stdout)
        handler.setLevel(level)
        if json_output:
            handler.setFormatter(JSONFormatter())
        else:
            handler.setFormatter(
                logging.Formatter("[%(asctime)s] %(levelname)s in %(name)s: %(message)s")
            )
        logger.addHandler(handler)

    return logger


logger = setup_logging()
