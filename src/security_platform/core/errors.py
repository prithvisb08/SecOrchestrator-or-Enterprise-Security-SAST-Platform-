"""Domain exception definitions for SecOrchestrator."""


class SecurityPlatformError(Exception):
    """Base exception for all domain errors in SecOrchestrator."""

    def __init__(self, message: str, details: dict[str, str] | None = None) -> None:
        super().__init__(message)
        self.message = message
        self.details = details or {}


class PathTraversalError(SecurityPlatformError):
    """Raised when an untrusted path attempts to escape the root workspace."""


class ArchiveSecurityError(SecurityPlatformError):
    """Raised when an uploaded archive violates security boundaries (zip slip, zip bomb, symlink)."""


class ScanError(SecurityPlatformError):
    """Raised when a scan cannot be completed."""


class EngineExecutionError(SecurityPlatformError):
    """Raised when an internal or external analysis engine fails."""
