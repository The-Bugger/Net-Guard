"""
backend/services/__init__.py — Service layer for NetGuard IDPS.

Exports the primary service classes so callers can import them from a single
location:

    from backend.services import LoggingEngine, setup_logging
"""

from backend.services.log_service import LoggingEngine, setup_logging, get_system_logger, get_detection_logger, get_error_logger

__all__ = [
    "LoggingEngine",
    "setup_logging",
    "get_system_logger",
    "get_detection_logger",
    "get_error_logger",
]
