# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0] - 2026-03-07

### Added
- `PyCVE` facade providing a single entry point to all library features.
- `lookup()` — fetch one or more CVEs from NIST NVD API v2 by ID.
- `lookup_from_file()` — parse CVE IDs from `.txt`, `.csv`, `.json`, `.xlsx` files and fetch them.
- `search()` — search NVD by keyword, severity, CPE, CWE, date range, KEV flag, CVE tag, and more.
- `patch_check()` — analyse patch availability for one or more CVEs.
- `generate_patch_file()` — download and save `.patch` files from GitHub commit/PR URLs.
- `stats()` — compute severity distribution, CVSS averages, and patch coverage over a list of CVEs.
- `history()` — retrieve NVD change history for a CVE with optional date range filter.
- `kev_check()` — check CVEs against the CISA Known Exploited Vulnerabilities catalog.
- `report()` — generate reports in JSON, HTML, PDF (fpdf2), and Excel (openpyxl) formats.
- `notify()` — send CVE alerts to Slack and Microsoft Teams via Incoming Webhooks.
- SQLite-backed response cache with configurable TTL.
- Token-bucket rate limiter respecting NVD's 5 req/30 s (public) and 50 req/30 s (API key) limits.
- Automatic pagination for large NVD result sets.
- YAML-based configuration file (`~/.pycve/config.yaml`) with env var and constructor overrides.
- Structured exception hierarchy (`PyCVEError` → `APIError`, `RateLimitError`, `CVENotFoundError`, etc.).
- Optional dependencies: `[reports]` for HTML/PDF/Excel, `[all]` for everything.
