"""pycve — Python library for CVE management using NIST NVD API v2.

Quick start::

    from pycve import PyCVE

    cve = PyCVE(api_key="your-nvd-api-key")   # api_key is optional
    result = cve.lookup("CVE-2021-44228")
    print(result.id, result.severity, result.cvss_score)
"""

from pycve.core import PyCVE

# Re-export the most-used models for convenience
from pycve.models import (
    CVERecord,
    CVEStats,
    CVSSScore,
    ChangeHistoryEvent,
    KEVEntry,
    PatchInfo,
    PatchStatus,
    Reference,
    Weakness,
)

# Re-export exception types
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

__all__ = [
    # Facade
    "PyCVE",
    # Models
    "CVERecord",
    "CVSSScore",
    "Reference",
    "Weakness",
    "PatchInfo",
    "PatchStatus",
    "KEVEntry",
    "ChangeHistoryEvent",
    "CVEStats",
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
]

__version__ = "1.0.0"
