"""Shared pytest fixtures for pycve test suite."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

# ── Helpers ────────────────────────────────────────────────────────────────

FIXTURES_DIR = Path(__file__).parent / "fixtures"


def load_fixture(name: str) -> dict:
    with (FIXTURES_DIR / name).open() as f:
        return json.load(f)


# ── Raw NVD JSON fixtures ──────────────────────────────────────────────────

@pytest.fixture
def raw_cve_response():
    return load_fixture("sample_cve_response.json")


@pytest.fixture
def raw_search_response():
    return load_fixture("sample_search_response.json")


@pytest.fixture
def raw_history_response():
    return load_fixture("sample_history_response.json")


@pytest.fixture
def raw_kev_catalog():
    return load_fixture("sample_kev_catalog.json")


# ── Model fixtures ─────────────────────────────────────────────────────────

@pytest.fixture
def cve_record(raw_cve_response):
    from pycve.models.cve import CVERecord
    vuln = raw_cve_response["vulnerabilities"][0]
    return CVERecord.from_nvd_json(vuln)


@pytest.fixture
def cve_record_list(raw_search_response):
    from pycve.models.cve import CVERecord
    return [CVERecord.from_nvd_json(v) for v in raw_search_response["vulnerabilities"]]
