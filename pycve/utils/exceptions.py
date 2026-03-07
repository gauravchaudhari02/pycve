"""Custom exception hierarchy for pycve."""


class PyCVEError(Exception):
    """Base exception for all pycve errors."""


# ── API / HTTP ──────────────────────────────────────────────────────────────


class APIError(PyCVEError):
    """Raised when the NVD API returns an unexpected response."""

    def __init__(self, message: str, status_code: int | None = None, url: str | None = None):
        super().__init__(message)
        self.status_code = status_code
        self.url = url


class RateLimitError(APIError):
    """Raised on HTTP 429 – Too Many Requests."""

    def __init__(self, retry_after: int | None = None):
        msg = "NVD API rate limit exceeded."
        if retry_after:
            msg += f" Retry after {retry_after}s."
        super().__init__(msg, status_code=429)
        self.retry_after = retry_after


class CVENotFoundError(APIError):
    """Raised when a requested CVE ID is not found in NVD (HTTP 404)."""

    def __init__(self, cve_id: str):
        super().__init__(f"CVE not found: {cve_id}", status_code=404)
        self.cve_id = cve_id


# ── Input Validation ────────────────────────────────────────────────────────


class InvalidCVEIdError(PyCVEError):
    """Raised when a CVE ID does not match the expected format."""

    def __init__(self, cve_id: str):
        super().__init__(
            f"Invalid CVE ID format: '{cve_id}'. "
            "Expected format: CVE-YYYY-NNNNN (e.g. CVE-2021-44228)."
        )
        self.cve_id = cve_id


# ── Config ──────────────────────────────────────────────────────────────────


class ConfigError(PyCVEError):
    """Raised for configuration file read/write failures."""


# ── Parsers ─────────────────────────────────────────────────────────────────


class ParserError(PyCVEError):
    """Raised when a CVE input file cannot be parsed."""

    def __init__(self, message: str, file_path: str | None = None):
        super().__init__(message)
        self.file_path = file_path


# ── Reports ─────────────────────────────────────────────────────────────────


class ReportError(PyCVEError):
    """Raised when report generation fails."""

    def __init__(self, message: str, format: str | None = None):
        super().__init__(message)
        self.format = format


class MissingDependencyError(ReportError):
    """Raised when an optional dependency required for a report format is missing."""

    def __init__(self, package: str, feature: str, extra: str):
        super().__init__(
            f"Package '{package}' is required for {feature}. "
            f"Install it with: pip install 'pycve[{extra}]'  or  uv pip install 'pycve[{extra}]'"
        )
        self.package = package
        self.extra = extra


# ── Notifications ───────────────────────────────────────────────────────────


class NotificationError(PyCVEError):
    """Raised when a notification webhook delivery fails."""

    def __init__(self, message: str, channel: str | None = None, status_code: int | None = None):
        super().__init__(message)
        self.channel = channel
        self.status_code = status_code
