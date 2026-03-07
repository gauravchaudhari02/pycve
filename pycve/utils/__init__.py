"""pycve.utils — Input validation and custom exceptions."""

from pycve.utils.exceptions import (
    APIError,
    CVENotFoundError,
    ConfigError,
    InvalidCVEIdError,
    MissingDependencyError,
    NotificationError,
    ParserError,
    PyCVEError,
    RateLimitError,
    ReportError,
)
from pycve.utils.validators import (
    extract_cve_ids_from_text,
    normalize_cve_id,
    validate_and_normalize_cve_ids,
    validate_cve_id,
    validate_date,
    validate_file_path,
    validate_severity,
)

__all__ = [
    # Exceptions
    "PyCVEError",
    "APIError",
    "RateLimitError",
    "CVENotFoundError",
    "InvalidCVEIdError",
    "ConfigError",
    "ParserError",
    "ReportError",
    "MissingDependencyError",
    "NotificationError",
    # Validators
    "validate_cve_id",
    "normalize_cve_id",
    "validate_and_normalize_cve_ids",
    "validate_severity",
    "validate_date",
    "validate_file_path",
    "extract_cve_ids_from_text",
]
