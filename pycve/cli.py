"""pycve command-line interface.

Entry point: ``pycve <command> [options]``

Exit codes
----------
0  Success
1  General error (API, config, I/O)
2  No results found
3  Invalid input (bad CVE ID, unknown argument)
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

# ── Exit codes ────────────────────────────────────────────────────────────────

EXIT_OK = 0
EXIT_ERROR = 1
EXIT_NO_RESULTS = 2
EXIT_INVALID_INPUT = 3

# ── Output helpers ────────────────────────────────────────────────────────────


def _print_json(data: Any) -> None:
    print(json.dumps(data, indent=2, default=str))


def _print_minimal(cves: list) -> None:
    """One line per CVE: ID  SEVERITY  SCORE"""
    for cve in cves:
        score = cve.cvss_score if cve.cvss_score is not None else "N/A"
        print(f"{cve.id:<20}  {cve.severity:<10}  {score}")


def _print_table(cves: list) -> None:
    """Human-readable aligned table."""
    if not cves:
        return
    header = f"{'CVE ID':<20}  {'SEV':<10}  {'SCORE':<6}  {'STATUS':<20}  DESCRIPTION"
    print(header)
    print("-" * len(header))
    for cve in cves:
        score = f"{cve.cvss_score:.1f}" if cve.cvss_score is not None else "N/A"
        desc = cve.description[:60] + "…" if len(cve.description) > 60 else cve.description
        status = cve.vuln_status[:20]
        print(f"{cve.id:<20}  {cve.severity:<10}  {score:<6}  {status:<20}  {desc}")


def _render_cves(cves: list, fmt: str, output: str | None) -> int:
    """Render CVE list in the requested format, optionally writing to a file."""
    if not cves:
        _warn("No CVEs found.")
        return EXIT_NO_RESULTS

    if fmt == "json":
        text = json.dumps([c.to_dict() for c in cves], indent=2, default=str)
    elif fmt == "minimal":
        lines = []
        for cve in cves:
            score = cve.cvss_score if cve.cvss_score is not None else "N/A"
            lines.append(f"{cve.id}  {cve.severity}  {score}")
        text = "\n".join(lines)
    else:  # table
        if output:
            # plain text table for file output
            rows = []
            for cve in cves:
                score = f"{cve.cvss_score:.1f}" if cve.cvss_score is not None else "N/A"
                rows.append(f"{cve.id}  {cve.severity}  {score}  {cve.vuln_status}  {cve.description[:80]}")
            text = "\n".join(rows)
        else:
            _print_table(cves)
            return EXIT_OK

    if output:
        Path(output).write_text(text, encoding="utf-8")
        print(f"Output written to: {output}")
    else:
        print(text)
    return EXIT_OK


def _warn(msg: str) -> None:
    print(f"[warn] {msg}", file=sys.stderr)


def _err(msg: str) -> None:
    print(f"[error] {msg}", file=sys.stderr)


# ── PyCVE factory ─────────────────────────────────────────────────────────────


def _make_client(args: argparse.Namespace):
    from pycve import PyCVE
    return PyCVE(
        api_key=getattr(args, "api_key", None) or None,
        enable_cache=not getattr(args, "no_cache", False),
    )


# ── Subcommand handlers ───────────────────────────────────────────────────────


def _cmd_lookup(args: argparse.Namespace) -> int:
    from pycve.utils.exceptions import PyCVEError

    client = _make_client(args)
    try:
        if args.file:
            cves = client.lookup_from_file(args.file)
        else:
            if not args.cve_ids:
                _err("Provide one or more CVE IDs or use --file.")
                return EXIT_INVALID_INPUT
            raw = client.lookup(args.cve_ids)
            cves = [raw] if not isinstance(raw, list) else raw
    except PyCVEError as exc:
        _err(str(exc))
        return EXIT_ERROR

    return _render_cves(cves, args.format, args.output)


def _cmd_search(args: argparse.Namespace) -> int:
    from pycve.utils.exceptions import PyCVEError

    client = _make_client(args)
    try:
        cves = client.search(
            keyword=args.keyword,
            keyword_exact=args.exact,
            severity=args.severity,
            severity_v4=args.severity_v4,
            cpe_name=args.cpe,
            cwe_id=args.cwe,
            cve_tag=args.cve_tag,
            has_kev=args.kev_only,
            has_cert_alerts=args.cert_alerts,
            is_vulnerable=args.is_vulnerable,
            pub_start_date=args.pub_start,
            pub_end_date=args.pub_end,
            mod_start_date=args.mod_start,
            mod_end_date=args.mod_end,
            limit=args.limit,
        )
    except PyCVEError as exc:
        _err(str(exc))
        return EXIT_ERROR

    return _render_cves(cves, args.format, args.output)


def _cmd_patch(args: argparse.Namespace) -> int:
    from pycve.utils.exceptions import PyCVEError

    client = _make_client(args)
    try:
        raw = client.patch_check(args.cve_ids)
        infos = [raw] if not isinstance(raw, list) else raw
    except PyCVEError as exc:
        _err(str(exc))
        return EXIT_ERROR

    if not infos:
        _warn("No results.")
        return EXIT_NO_RESULTS

    if args.format == "json":
        _print_json([i.to_dict() for i in infos])
    else:
        header = f"{'CVE ID':<20}  {'STATUS':<12}  PATCH URLS"
        print(header)
        print("-" * 60)
        for info in infos:
            urls = ", ".join(info.patch_urls[:2]) or "—"
            print(f"{info.cve_id:<20}  {info.status.value:<12}  {urls}")
    return EXIT_OK


def _cmd_kev(args: argparse.Namespace) -> int:
    from pycve.utils.exceptions import PyCVEError

    client = _make_client(args)
    try:
        raw = client.kev_check(args.cve_ids)
        entries = [raw] if not isinstance(raw, list) else raw
    except PyCVEError as exc:
        _err(str(exc))
        return EXIT_ERROR

    if not entries:
        _warn("No results.")
        return EXIT_NO_RESULTS

    if args.format == "json":
        _print_json([e.to_dict() for e in entries])
    else:
        header = f"{'CVE ID':<20}  {'IN KEV':<8}  {'DUE DATE':<12}  VENDOR / PRODUCT"
        print(header)
        print("-" * 65)
        for e in entries:
            in_kev = "YES" if e.in_kev_catalog else "NO"
            due = e.due_date.strftime("%Y-%m-%d") if e.due_date else "—"
            vendor = f"{e.vendor_project} / {e.product}" if e.in_kev_catalog else "—"
            print(f"{e.cve_id:<20}  {in_kev:<8}  {due:<12}  {vendor}")
    return EXIT_OK


def _cmd_history(args: argparse.Namespace) -> int:
    from pycve.utils.exceptions import PyCVEError

    client = _make_client(args)
    try:
        events = client.history(
            args.cve_id,
            change_start_date=args.start,
            change_end_date=args.end,
        )
    except PyCVEError as exc:
        _err(str(exc))
        return EXIT_ERROR

    if not events:
        _warn("No history events found.")
        return EXIT_NO_RESULTS

    if args.format == "json":
        _print_json([e.to_dict() for e in events])
    else:
        print(f"Change history for {args.cve_id} ({len(events)} event(s))\n")
        for ev in events:
            created = ev.created.strftime("%Y-%m-%d %H:%M") if ev.created else "unknown"
            print(f"  {created}  {ev.event_name}")
            for d in ev.details:
                old = f" (was: {d.old_value})" if d.old_value else ""
                print(f"    • {d.action} {d.type}: {d.new_value}{old}")
    return EXIT_OK


def _cmd_report(args: argparse.Namespace) -> int:
    from pycve.utils.exceptions import PyCVEError, MissingDependencyError

    client = _make_client(args)
    try:
        cves = client.lookup_from_file(args.file)
        if not cves:
            _warn("No CVEs found in file.")
            return EXIT_NO_RESULTS
        path = client.report(cves, format=args.format, output=args.output)
        print(f"Report written to: {path}")
    except MissingDependencyError as exc:
        _err(str(exc))
        return EXIT_ERROR
    except PyCVEError as exc:
        _err(str(exc))
        return EXIT_ERROR
    return EXIT_OK


def _cmd_config(args: argparse.Namespace) -> int:
    from pycve import PyCVE
    from pycve.utils.exceptions import ConfigError

    client = PyCVE()
    try:
        if args.config_cmd == "set":
            client.config.set(args.key, args.value)
            print(f"Set {args.key} = {args.value}")
        elif args.config_cmd == "get":
            val = client.config.get(args.key)
            print(val if val is not None else "(not set)")
        elif args.config_cmd == "list":
            settings = client.config.list()
            if getattr(args, "format", "table") == "json":
                _print_json(settings)
            else:
                col = max(len(k) for k in settings)
                for k, v in settings.items():
                    print(f"{k:<{col}}  {v}")
        elif args.config_cmd == "reset":
            client.config.reset(args.key if hasattr(args, "key") else None)
            target = args.key if hasattr(args, "key") and args.key else "all keys"
            print(f"Reset {target} to defaults.")
    except ConfigError as exc:
        _err(str(exc))
        return EXIT_ERROR
    return EXIT_OK


def _cmd_cache(args: argparse.Namespace) -> int:
    from pycve import PyCVE

    client = PyCVE()
    if client.cache is None:
        _err("Cache is disabled.")
        return EXIT_ERROR

    if args.cache_cmd == "stats":
        stats = client.cache.stats()
        if getattr(args, "format", "table") == "json":
            _print_json(stats)
        else:
            for k, v in stats.items():
                print(f"{k:<20}  {v}")
    elif args.cache_cmd == "clear":
        n = client.cache.clear()
        print(f"Cache cleared ({n} entries removed).")
    return EXIT_OK


# ── Parser construction ───────────────────────────────────────────────────────

_FORMAT_CHOICES = ["table", "json", "minimal"]
_SEVERITY_CHOICES = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]


def _add_common(parser: argparse.ArgumentParser) -> None:
    """Add flags shared by most commands."""
    parser.add_argument("--api-key", metavar="KEY", help="NVD API key (overrides config/env)")
    parser.add_argument("--no-cache", action="store_true", help="Disable cache for this call")
    parser.add_argument("--format", choices=_FORMAT_CHOICES, default="table",
                        help="Output format (default: table)")
    parser.add_argument("--output", metavar="PATH", help="Write output to file instead of stdout")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="pycve",
        description="CVE management CLI powered by the NIST NVD API v2.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
examples:
  pycve lookup CVE-2021-44228
  pycve lookup CVE-2021-44228 CVE-2023-44487 --format json
  pycve lookup --file cves.csv --format minimal
  pycve search --keyword log4j --severity CRITICAL --limit 10
  pycve search --kev-only --severity HIGH --format json
  pycve patch CVE-2021-44228
  pycve kev CVE-2021-44228 CVE-2023-44487
  pycve history CVE-2021-44228 --start 2022-01-01
  pycve report --file cves.txt --format html --output report.html
  pycve config set api_key YOUR_KEY
  pycve config list
  pycve cache stats
  pycve cache clear
""",
    )
    parser.add_argument("--version", action="version", version="%(prog)s 1.0.0")

    sub = parser.add_subparsers(dest="command", metavar="<command>")
    sub.required = True

    # ── lookup ──────────────────────────────────────────────────────────────
    p_lookup = sub.add_parser("lookup", help="Fetch CVEs by ID or from a file")
    _add_common(p_lookup)
    p_lookup.add_argument("cve_ids", nargs="*", metavar="CVE-ID",
                          help="One or more CVE IDs (e.g. CVE-2021-44228)")
    p_lookup.add_argument("--file", metavar="PATH",
                          help="Read CVE IDs from a file (.txt/.csv/.json/.xlsx)")
    p_lookup.set_defaults(func=_cmd_lookup)

    # ── search ──────────────────────────────────────────────────────────────
    p_search = sub.add_parser("search", help="Search NVD for CVEs matching filters")
    _add_common(p_search)
    p_search.add_argument("--keyword", metavar="TEXT", help="Free-text keyword search")
    p_search.add_argument("--exact", action="store_true", help="Exact keyword match")
    p_search.add_argument("--severity", choices=_SEVERITY_CHOICES, metavar="SEV",
                          help="CVSS v3 severity filter")
    p_search.add_argument("--severity-v4", dest="severity_v4", choices=_SEVERITY_CHOICES,
                          metavar="SEV", help="CVSS v4 severity filter")
    p_search.add_argument("--cpe", metavar="CPE", help="CPE 2.3 URI filter")
    p_search.add_argument("--cwe", metavar="CWE-ID", help="CWE identifier filter (e.g. CWE-79)")
    p_search.add_argument("--cve-tag", dest="cve_tag", metavar="TAG",
                          help="NVD CVE tag (e.g. disputed)")
    p_search.add_argument("--kev-only", action="store_true",
                          help="Only return CVEs in CISA KEV catalog")
    p_search.add_argument("--cert-alerts", action="store_true",
                          help="Only return CVEs with US-CERT alerts")
    p_search.add_argument("--is-vulnerable", dest="is_vulnerable", action="store_true",
                          help="Require CPE to be marked vulnerable (use with --cpe)")
    p_search.add_argument("--pub-start", metavar="DATE", help="Published on or after (YYYY-MM-DD)")
    p_search.add_argument("--pub-end", metavar="DATE", help="Published on or before (YYYY-MM-DD)")
    p_search.add_argument("--mod-start", metavar="DATE", help="Modified on or after (YYYY-MM-DD)")
    p_search.add_argument("--mod-end", metavar="DATE", help="Modified on or before (YYYY-MM-DD)")
    p_search.add_argument("--limit", type=int, metavar="N", help="Maximum results to return")
    p_search.set_defaults(func=_cmd_search)

    # ── patch ───────────────────────────────────────────────────────────────
    p_patch = sub.add_parser("patch", help="Check patch availability for CVEs")
    _add_common(p_patch)
    p_patch.add_argument("cve_ids", nargs="+", metavar="CVE-ID")
    p_patch.set_defaults(func=_cmd_patch)

    # ── kev ─────────────────────────────────────────────────────────────────
    p_kev = sub.add_parser("kev", help="Check CVEs against CISA KEV catalog")
    _add_common(p_kev)
    p_kev.add_argument("cve_ids", nargs="+", metavar="CVE-ID")
    p_kev.set_defaults(func=_cmd_kev)

    # ── history ─────────────────────────────────────────────────────────────
    p_hist = sub.add_parser("history", help="Show NVD change history for a CVE")
    _add_common(p_hist)
    p_hist.add_argument("cve_id", metavar="CVE-ID")
    p_hist.add_argument("--start", metavar="DATE", help="History start date (YYYY-MM-DD)")
    p_hist.add_argument("--end", metavar="DATE", help="History end date (YYYY-MM-DD)")
    p_hist.set_defaults(func=_cmd_history)

    # ── report ──────────────────────────────────────────────────────────────
    p_report = sub.add_parser("report", help="Generate a report from a CVE list file")
    p_report.add_argument("--api-key", metavar="KEY")
    p_report.add_argument("--no-cache", action="store_true")
    p_report.add_argument("--file", required=True, metavar="PATH",
                          help="Input file with CVE IDs (.txt/.csv/.json/.xlsx)")
    p_report.add_argument("--format", choices=["json", "html", "pdf", "excel"],
                          default="json", help="Report format (default: json)")
    p_report.add_argument("--output", metavar="PATH", help="Output file path")
    p_report.set_defaults(func=_cmd_report)

    # ── config ──────────────────────────────────────────────────────────────
    p_cfg = sub.add_parser("config", help="Manage pycve configuration")
    cfg_sub = p_cfg.add_subparsers(dest="config_cmd", metavar="<subcommand>")
    cfg_sub.required = True

    p_cfg_set = cfg_sub.add_parser("set", help="Set a config value")
    p_cfg_set.add_argument("key", help="Config key")
    p_cfg_set.add_argument("value", help="Value to set")

    p_cfg_get = cfg_sub.add_parser("get", help="Get a config value")
    p_cfg_get.add_argument("key", help="Config key")

    p_cfg_list = cfg_sub.add_parser("list", help="List all config values")
    p_cfg_list.add_argument("--format", choices=["table", "json"], default="table")

    p_cfg_reset = cfg_sub.add_parser("reset", help="Reset config key(s) to defaults")
    p_cfg_reset.add_argument("key", nargs="?", help="Key to reset (omit to reset all)")

    p_cfg.set_defaults(func=_cmd_config)

    # ── cache ───────────────────────────────────────────────────────────────
    p_cache = sub.add_parser("cache", help="Manage the local response cache")
    cache_sub = p_cache.add_subparsers(dest="cache_cmd", metavar="<subcommand>")
    cache_sub.required = True
    p_cache_stats = cache_sub.add_parser("stats", help="Show cache statistics")
    p_cache_stats.add_argument("--format", choices=["table", "json"], default="table")
    cache_sub.add_parser("clear", help="Clear all cached entries")
    p_cache.set_defaults(func=_cmd_cache)

    return parser


# ── Entry point ───────────────────────────────────────────────────────────────


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return args.func(args)
    except KeyboardInterrupt:
        print("\nAborted.", file=sys.stderr)
        return EXIT_ERROR
    except Exception as exc:  # noqa: BLE001
        _err(f"Unexpected error: {exc}")
        return EXIT_ERROR


if __name__ == "__main__":
    sys.exit(main())
