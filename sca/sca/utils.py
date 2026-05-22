# """
# Structured logging wrapper using structlog, respecting SCA_LOG_LEVEL.
# """

# import logging
# import os
# import sys

# import structlog


# def configure_logging(level: str = "INFO") -> None:
#     """
#     Set up structlog to output JSON on stdout.

#     The log level can be overridden by the SCA_LOG_LEVEL environment variable.
#     """
#     log_level = os.environ.get("SCA_LOG_LEVEL", level).upper()
#     numeric_level = getattr(logging, log_level, logging.INFO)

#     structlog.configure(
#         processors=[
#             structlog.stdlib.add_log_level,
#             structlog.stdlib.PositionalArgumentsFormatter(),
#             structlog.processors.TimeStamper(fmt="iso"),
#             structlog.processors.StackInfoRenderer(),
#             structlog.processors.format_exc_info,
#             structlog.processors.UnicodeDecoder(),
#             structlog.dev.ConsoleRenderer()
#             if sys.stdout.isatty()
#             else structlog.processors.JSONRenderer(),
#         ],
#         context_class=dict,
#         logger_factory=structlog.PrintLoggerFactory(),
#         wrapper_class=structlog.BoundLogger,
#         cache_logger_on_first_use=True,
#     )

#     # Set root logger level so that standard logging plays nicely
#     logging.basicConfig(format="%(message)s", stream=sys.stdout, level=numeric_level)


# def get_logger(name: str) -> structlog.BoundLogger:
#     """Return a bound structlog logger for the given module."""
#     configure_logging()  # safe to call multiple times
#     return structlog.get_logger(name)


import logging
import os
import sys


# Lightweight logging setup - avoid structlog on Windows/Python 3.13 to prevent TP_NUM_C_BUFS errors
_CONFIGURED = False


def configure_logging(level: str = "INFO") -> None:
    """Configure logging using standard library only (lightweight, no structlog overhead)."""
    global _CONFIGURED
    
    if _CONFIGURED:
        return
    
    log_level = os.environ.get("SCA_LOG_LEVEL", level).upper()
    numeric_level = getattr(logging, log_level, logging.INFO)

    # Simple standard library configuration
    logging.basicConfig(
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
        stream=sys.stdout,
        level=numeric_level,
        force=True
    )
    _CONFIGURED = True


class SimpleLogger:
    """Lightweight logger wrapper compatible with expected API."""
    
    def __init__(self, name: str):
        self.logger = logging.getLogger(name)
    
    def debug(self, msg: str, **kwargs):
        self.logger.debug(f"{msg} {kwargs}" if kwargs else msg)
    
    def info(self, msg: str, **kwargs):
        self.logger.info(f"{msg} {kwargs}" if kwargs else msg)
    
    def warning(self, msg: str, **kwargs):
        self.logger.warning(f"{msg} {kwargs}" if kwargs else msg)
    
    def error(self, msg: str, **kwargs):
        self.logger.error(f"{msg} {kwargs}" if kwargs else msg)
    
    def critical(self, msg: str, **kwargs):
        self.logger.critical(f"{msg} {kwargs}" if kwargs else msg)


def get_logger(name: str) -> SimpleLogger:
    """Return a lightweight logger for the given module."""
    configure_logging()
    return SimpleLogger(name)