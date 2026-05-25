"""Custom exceptions for the SCA toolkit."""

class SCAError(Exception):
    """Base exception for all SCA errors."""
    pass

class DependencyResolutionError(SCAError):
    """Raised when a dependency resolver fails."""
    pass

class ScanCodeError(SCAError):
    """Raised when ScanCode execution fails."""
    pass

class NetworkError(SCAError):
    """Raised when a network operation times out or fails."""
    pass