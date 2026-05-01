# PyCVE

A **library-first** Python package for CVE management using the [NIST NVD API v2](https://nvd.nist.gov/developers/vulnerabilities) and [CISA KEV catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog).

## Features

| Feature | Method |
|---|---|
| Lookup CVEs (single / multiple / from file) | `cve.lookup()`, `cve.lookup_from_file()` |
| Search NVD by keyword, severity, date, CPE | `cve.search()` |
| Generate reports (HTML / JSON / PDF / Excel) | `cve.report()` |
| Patch availability analysis | `cve.patch_check()` |
| Download & save patch files locally | `cve.generate_patch_file()` |
| Severity & CVSS statistics | `cve.stats()` |
| CVE change history | `cve.history()` |
| CISA KEV catalog lookup | `cve.kev_check()` |
| Send alerts to Slack / Teams | `cve.notify()` |
| Configuration management | `cve.config.set/get/list/reset()` |
| Cache management (SQLite) | `cve.cache.stats/clear()` |

## Installation

### pip
```bash
pip install pycve                    # core only
pip install "pycve[reports]"         # + HTML/PDF/Excel report generators
pip install "pycve[all]"             # everything
```

### uv (recommended)
```bash
uv pip install pycve
uv pip install "pycve[reports]"
uv pip install "pycve[all]"
```

### Development
```bash
git clone https://github.com/gauravchaudhari02/pycve.git
cd pycve

# pip
pip install -e ".[dev]"

# uv
uv sync --all-extras
```

## Quick Start

```python
from pycve import PyCVE

cve = PyCVE(api_key="your-nvd-api-key")  # API key optional but recommended

# Lookup a single CVE
result = cve.lookup("CVE-2021-44228")
print(result.id, result.cvss_scores[0].severity, result.cvss_scores[0].score)
# → CVE-2021-44228 CRITICAL 10.0

# Lookup multiple CVEs
results = cve.lookup(["CVE-2021-44228", "CVE-2023-44487"])

# From file (CSV / Excel / JSON / TXT)
results = cve.lookup_from_file("vulnerabilities.csv")

# Search NVD
results = cve.search(keyword="log4j", severity="CRITICAL", limit=10)

# Patch check
patch = cve.patch_check("CVE-2021-44228")
print(patch.status)          # PATCHED
print(patch.patch_urls)      # ['https://github.com/...']

# Download patch file(s) locally
# Single patch → returns path string
path = cve.generate_patch_file("CVE-2021-44228", output="/tmp/patches")
print(path)   # /tmp/patches/CVE_2021_44228_1.patch

# Multiple patches → separate .patch files (default)
paths = cve.generate_patch_file("CVE-2021-44228", output="/tmp/patches")
print(paths)  # ['/tmp/patches/CVE_2021_44228_1.patch', '/tmp/patches/CVE_2021_44228_2.patch']

# Multiple patches → combined into one file
path = cve.generate_patch_file("CVE-2021-44228", output="/tmp/all.patch", combine=True)

# No patch available → returns None
print(cve.generate_patch_file("CVE-2023-99999"))  # None

# Severity statistics
stats = cve.stats(results)
print(stats.severity_distribution)  # {'CRITICAL': 5, 'HIGH': 3, ...}
print(stats.patch_coverage)         # 0.75

# CVE change history
history = cve.history("CVE-2021-44228")
for event in history:
    print(event.event_name, event.created)

# CISA KEV check
kev = cve.kev_check("CVE-2021-44228")
print(kev.in_kev_catalog, kev.due_date)

# Generate report
cve.report(results, format="html", output="report.html")
cve.report(results, format="json", output="report.json")
cve.report(results, format="pdf",  output="report.pdf")
cve.report(results, format="excel", output="report.xlsx")

# Send notifications
from pycve.notifications import SlackNotifier, TeamsNotifier

cve.notify(
    cves=results,
    notifier=SlackNotifier(webhook_url="https://hooks.slack.com/services/..."),
    template="critical_alert",
)
cve.notify(
    cves=results,
    notifier=TeamsNotifier(webhook_url="https://outlook.office.com/webhook/..."),
    template="summary",
)

# Or configure webhooks once
cve.config.set("slack_webhook_url", "https://hooks.slack.com/services/...")
cve.config.set("teams_webhook_url", "https://outlook.office.com/webhook/...")
cve.notify(cves=results, channel="slack")
cve.notify(cves=results, channel="teams")

# Config management
cve.config.set("api_key", "your-key")
cve.config.get("api_key")
cve.config.list()
cve.config.reset()

# Cache management
cve.cache.stats()   # {'entries': 142, 'size_mb': 3.2, 'hit_rate': 0.87}
cve.cache.clear()
```

## CLI Usage

After installation a `pycve` command is available in your shell.

```bash
# Lookup CVEs
pycve lookup CVE-2021-44228
pycve lookup CVE-2021-44228 CVE-2023-44487 --format json
pycve lookup --file vulnerabilities.csv --format minimal

# Search NVD
pycve search --keyword log4j --severity CRITICAL --limit 10
pycve search --kev-only --severity HIGH --format json
pycve search --cpe "cpe:2.3:a:apache:log4j:*" --is-vulnerable --limit 20
pycve search --pub-start 2024-01-01 --pub-end 2024-03-31 --severity CRITICAL

# Patch availability
pycve patch CVE-2021-44228
pycve patch CVE-2021-44228 CVE-2023-44487 --format json

# CISA KEV catalog
pycve kev CVE-2021-44228
pycve kev CVE-2021-44228 CVE-2023-44487 --format json

# Change history
pycve history CVE-2021-44228
pycve history CVE-2021-44228 --start 2022-01-01 --end 2023-01-01

# Generate reports
pycve report --file cves.txt --format html --output report.html
pycve report --file cves.csv --format pdf  --output report.pdf
pycve report --file cves.json --format excel --output report.xlsx

# Configuration
pycve config set api_key YOUR_NVD_API_KEY
pycve config get api_key
pycve config list
pycve config list --format json
pycve config reset api_key   # reset one key
pycve config reset           # reset all

# Cache
pycve cache stats
pycve cache stats --format json
pycve cache clear
```

### Output formats

| Flag | Description |
|---|---|
| `--format table` | Human-readable aligned table (default) |
| `--format json` | Machine-readable JSON — pipe to `jq` |
| `--format minimal` | One line per CVE: `ID  SEVERITY  SCORE` — ideal for scripts |

### Global flags

| Flag | Description |
|---|---|
| `--api-key KEY` | Override NVD API key for this call |
| `--no-cache` | Bypass the local cache for this call |
| `--output PATH` | Write output to a file instead of stdout |

### Exit codes

| Code | Meaning |
|---|---|
| `0` | Success |
| `1` | Error (API, config, I/O) |
| `2` | No results found |
| `3` | Invalid input |

### CI pipeline example

```bash
# Fail the build if any CRITICAL CVE is found in a dependency scan
pycve lookup --file scan.csv --format json \
  | jq -e '[.[] | select(.severity == "CRITICAL")] | length > 0' \
  && { echo "CRITICAL CVEs found!"; exit 1; }
```

## Configuration

Settings are stored in `~/.pycve/config.yaml`. Precedence (highest → lowest):

1. Constructor parameter: `PyCVE(api_key="...")`
2. Environment variable: `NVD_API_KEY`
3. Config file: `~/.pycve/config.yaml`
4. Default value

### Available Settings

| Key | Default | Env Var | Description |
|---|---|---|---|
| `api_key` | `None` | `NVD_API_KEY` | NVD API key (5 req/30s without, 50 with) |
| `cache_ttl` | `86400` | `PYCVE_CACHE_TTL` | Cache TTL in seconds |
| `default_report_format` | `json` | — | Default report format |
| `output_dir` | `.` | — | Default output directory |
| `slack_webhook_url` | `None` | `PYCVE_SLACK_WEBHOOK` | Slack Incoming Webhook URL |
| `teams_webhook_url` | `None` | `PYCVE_TEAMS_WEBHOOK` | Teams Incoming Webhook URL |

## API Key

Get a free NVD API key at: https://nvd.nist.gov/developers/request-an-api-key

Without a key: **5 requests per 30 seconds**  
With a key: **50 requests per 30 seconds**

## Requirements

- `Python` ≥ 3.10
- `requests` ≥ 2.31
- `pyyaml` ≥ 6.0

Optional (for reports):
- `jinja2` ≥ 3.1 (HTML reports)
- `openpyxl` ≥ 3.1 (Excel reports)
- `fpdf2` ≥ 2.7 (PDF reports)

## Contributing

Contributions are welcome! Please open an issue or pull request on GitHub.
See [CONTRIBUTING.md](CONTRIBUTING.md) for the full guide on setting up a dev environment, code style, and the PR process.

## Changelog

See [CHANGELOG.md](CHANGELOG.md) for a full history of changes.

## License

This project is licensed under the MIT License — see the [LICENSE](LICENSE) file for details.
