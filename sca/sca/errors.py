"""Custom exceptions and error handling for SCA."""

from __future__ import annotations

import signal
from typing import List, Optional


class SCAError(Exception):
    """Base exception for all SCA errors."""
    pass


class DependencyResolutionError(SCAError):
    """Raised when dependency resolution fails."""
    pass


class ScanCodeError(SCAError):
    """Raised when ScanCode scanning fails."""
    pass


class VulnerabilityMapperError(SCAError):
    """Raised when vulnerability mapping fails."""
    pass


class ConfigError(SCAError):
    """Raised when configuration is invalid."""
    pass


class TimeoutError(SCAError):
    """Raised when an operation exceeds timeout."""
    pass


class NetworkError(SCAError):
    """Raised when network requests fail."""
    pass


class ScanResult:
    """Result of a scan that may include partial results and errors."""
    
    def __init__(self):
        self.findings: dict = {}
        self.errors: List[str] = []
        self.warnings: List[str] = []
        self.partial_result: bool = False
    
    def add_error(self, error: str, severity: str = "error"):
        """Add an error or warning."""
        if severity == "error":
            self.errors.append(error)
            self.partial_result = True
        else:
            self.warnings.append(error)
    
    def success(self) -> bool:
        """Return True if no fatal errors occurred."""
        return not self.partial_result


class SignalHandler:
    """Handle graceful shutdown on SIGINT/SIGTERM."""
    
    _shutdown_requested = False
    
    @classmethod
    def setup(cls):
        """Register signal handlers."""
        signal.signal(signal.SIGINT, cls._handle_signal)
        signal.signal(signal.SIGTERM, cls._handle_signal)
    
    @staticmethod
    def _handle_signal(signum, frame):
        SignalHandler._shutdown_requested = True
        raise KeyboardInterrupt("Received signal, shutting down gracefully...")
    
    @classmethod
    def is_shutdown_requested(cls) -> bool:
        """Check if shutdown was requested."""
        return cls._shutdown_requested
    
    @classmethod
    def reset(cls):
        """Reset the shutdown flag."""
        cls._shutdown_requested = False


class RetryConfig:
    """Configuration for retry logic."""
    
    def __init__(
        self,
        max_retries: int = 3,
        initial_delay: float = 1.0,
        max_delay: float = 60.0,
        exponential_base: float = 2.0,
    ):
        self.max_retries = max_retries
        self.initial_delay = initial_delay
        self.max_delay = max_delay
        self.exponential_base = exponential_base
    
    def get_delay(self, attempt: int) -> float:
        """Calculate delay for attempt number (0-indexed)."""
        delay = self.initial_delay * (self.exponential_base ** attempt)
        return min(delay, self.max_delay)


def retry_with_backoff(
    func,
    *args,
    max_retries: int = 3,
    initial_delay: float = 1.0,
    exceptions: tuple = (Exception,),
    **kwargs,
):
    """Retry a function with exponential backoff."""
    import time
    
    config = RetryConfig(
        max_retries=max_retries,
        initial_delay=initial_delay,
    )
    
    last_exception = None
    for attempt in range(max_retries + 1):
        try:
            return func(*args, **kwargs)
        except exceptions as e:
            last_exception = e
            if attempt < max_retries:
                delay = config.get_delay(attempt)
                time.sleep(delay)
            continue
    
    raise last_exception or SCAError("Retry exhausted")
