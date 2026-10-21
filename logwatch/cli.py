"""Command-line interface and predictable exit codes for CI use."""

import argparse
import json
import os
import sys
import tempfile
import tomllib
from dataclasses import fields
from pathlib import Path

from . import __version__
from .detector import build_report
from .models import Config
from .parsers import load_events
from .reporting import render_html


def load_config(path: Path | None) -> Config:
    if path is None:
        return Config()
    with path.open("rb") as stream:
        data = tomllib.load(stream)
    if data.keys() - {"detection"}:
        raise ValueError("config accepts only a [detection] table")
    settings = data.get("detection", {})
    if not isinstance(settings, dict) or settings.keys() - {field.name for field in fields(Config)}:
        raise ValueError("unknown detection configuration field")
    return Config(**settings)


def _write(path: Path, contents: str) -> None:
    """Replace each report atomically; clean up temporary files on errors."""
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", newline="\n", dir=path.parent, delete=False) as stream:
            temporary = Path(stream.name)
            stream.write(contents)
        os.replace(temporary, path)
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Offline authentication-log triage and evidence reports.")
    parser.add_argument("--version", action="version", version=__version__)
    commands = parser.add_subparsers(dest="command", required=True)
    analyze = commands.add_parser("analyze", help="analyze local CloudTrail, JSONL, or ISO 8601 OpenSSH logs")
    analyze.add_argument("input", type=Path)
    analyze.add_argument("--format", choices=("auto", "jsonl", "openssh", "cloudtrail"), default="auto")
    analyze.add_argument("--config", type=Path, help="TOML detection thresholds")
    analyze.add_argument("--json", type=Path, dest="json_path", help="write a machine-readable report")
    analyze.add_argument("--html", type=Path, dest="html_path", help="write a standalone HTML report")
    analyze.add_argument("--strict", action="store_true", help="fail without writing reports if any line is rejected")
    analyze.add_argument("--fail-on", choices=("none", "medium", "high"), default="none", help="exit 1 when an alert at this severity or higher is present")
    args = parser.parse_args(argv)
    try:
        protected = [args.input.resolve()]
        if args.config:
            protected.append(args.config.resolve())
        outputs = [path.resolve() for path in (args.json_path, args.html_path) if path]
        if len(outputs) != len(set(outputs)) or any(path in protected for path in outputs):
            raise ValueError("report paths must be distinct from each other, the input, and config")
        config = load_config(args.config)
        loaded = load_events(args.input, args.format)
        if args.strict and loaded.rejected_lines:
            raise ValueError(f"strict mode rejected {loaded.rejected_lines} record(s)")
        if not loaded.events:
            raise ValueError("no supported authentication events were found")
        report = build_report(loaded, config, args.input.name)
        if args.json_path:
            _write(args.json_path, json.dumps(report, indent=2, ensure_ascii=True) + "\n")
        if args.html_path:
            _write(args.html_path, render_html(report))
        stats = report["summary"]
        print(f"LogWatch | {stats['parsed_events']} events | {stats['failures']} failures | {stats['successes']} successes")
        print(f"Alerts: {stats['alerts']} ({stats['high']} high, {stats['medium']} medium) | Rejected records: {stats['rejected_records']}")
        if loaded.ignored_records:
            print(f"Ignored non-target CloudTrail records: {loaded.ignored_records}")
        for alert in report["alerts"]:
            print(f"[{alert['severity'].upper()}] {alert['rule_id']} {alert['source_ip']} -> {ascii(alert['host'])}: {alert['title']}")
        if loaded.rejected_lines:
            print("Warning: partial input; inspect the JSON/HTML diagnostics or rerun with --strict.", file=sys.stderr)
        if args.fail_on == "high" and stats["high"]:
            return 1
        if args.fail_on == "medium" and stats["alerts"]:
            return 1
        return 0
    except (OSError, ValueError, UnicodeError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
