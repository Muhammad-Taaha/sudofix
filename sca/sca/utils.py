"""
Structured logging wrapper using structlog, respecting SCA_LOG_LEVEL.
"""

import logging
import os
import sys

import structlog


def configure_logging(level: str = "INFO") -> None:
    """
    Set up structlog to output JSON on stdout.

    The log level can be overridden by the SCA_LOG_LEVEL environment variable.
    """
    log_level = os.environ.get("SCA_LOG_LEVEL", level).upper()
    numeric_level = getattr(logging, log_level, logging.INFO)

    structlog.configure(
        processors=[
            structlog.stdlib.add_log_level,
            structlog.stdlib.PositionalArgumentsFormatter(),
            structlog.processors.TimeStamper(fmt="iso"),
            structlog.processors.StackInfoRenderer(),
            structlog.processors.format_exc_info,
            structlog.processors.UnicodeDecoder(),
            structlog.dev.ConsoleRenderer() if sys.stdout.isatty() else structlog.processors.JSONRenderer(),
        ],
        context_class=dict,
        logger_factory=structlog.PrintLoggerFactory(),
        wrapper_class=structlog.BoundLogger,
        cache_logger_on_first_use=True,
    )

    # Set root logger level so that standard logging plays nicely
    logging.basicConfig(format="%(message)s", stream=sys.stdout, level=numeric_level)


def get_logger(name: str) -> structlog.BoundLogger:
    """Return a bound structlog logger for the given module."""
    configure_logging()  # safe to call multiple times
    return structlog.get_logger(name)