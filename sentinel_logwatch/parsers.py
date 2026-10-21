"""Strict JSONL and timestamped OpenSSH parsers; no log content is executed."""

import ipaddress
import json
import re
from datetime import datetime, timezone
from pathlib import Path

from .models import Event, LoadResult

MAX_LINE_LENGTH = 65_536
MAX_EVENTS = 200_000
METHODS = {"password", "publickey", "keyboard-interactive", "aws-console"}
TIMESTAMP = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})")
OPENSSH = re.compile(
    r"^(?P<timestamp>\S+)\s+(?P<host>\S+)\s+sshd(?:-session)?(?:\[\d+\])?:\s+"
    r"(?P<outcome>Failed|Accepted)\s+"
    r"(?P<method>password|publickey|keyboard-interactive(?:/pam)?)\s+"
    r"for\s+(?:invalid user\s+)?(?P<user>\S+)\s+from\s+"
    r"(?P<source_ip>\S+)\s+port\s+\d+(?:\s+.*)?$"
)


class ParseError(ValueError):
    """An unsupported or invalid input record."""


def _text(value: object, name: str) -> str:
    if not isinstance(value, str) or not value or len(value) > 255:
        raise ParseError(f"{name} must be a nonempty string of at most 255 characters")
    if any(not char.isprintable() for char in value):
        raise ParseError(f"{name} contains control characters")
    return value


def _unique_keys(pairs: list[tuple[str, object]]) -> dict:
    result = {}
    for key, value in pairs:
        if key in result:
            raise ParseError("duplicate JSON field")
        result[key] = value
    return result


def parse_line(text: str, line: int, format_name: str = "auto") -> Event:
    if format_name not in {"auto", "jsonl", "openssh"}:
        raise ValueError("unsupported input format")
    selected = ("jsonl" if text.lstrip().startswith("{") else "openssh") if format_name == "auto" else format_name
    if selected == "jsonl":
        try:
            record = json.loads(text, object_pairs_hook=_unique_keys)
        except (json.JSONDecodeError, RecursionError) as exc:
            raise ParseError("invalid JSON record") from exc
        if not isinstance(record, dict):
            raise ParseError("JSON record must be an object")
        required = {"timestamp", "host", "user", "source_ip", "outcome"}
        if not required <= record.keys():
            raise ParseError("missing required JSON fields")
        if record.keys() - required - {"method", "mfa_used", "identity_type"}:
            raise ParseError("unknown JSON fields; see the documented schema")
    else:
        match = OPENSSH.fullmatch(text.strip())
        if not match:
            raise ParseError("unsupported OpenSSH record; expected an ISO 8601 authentication line")
        record = match.groupdict()
        record["outcome"] = "failure" if record["outcome"] == "Failed" else "success"
        record["method"] = record["method"].replace("/pam", "")

    return normalize_record(record, line)


def normalize_record(record: dict, line: int, record_index: int | None = None) -> Event:
    """Validate normalized records shared by local and cloud adapters."""
    timestamp_text = _text(record["timestamp"], "timestamp")
    if not TIMESTAMP.fullmatch(timestamp_text):
        raise ParseError("timestamp must include a date, time, seconds, and UTC offset")
    try:
        timestamp = datetime.fromisoformat(timestamp_text.replace("Z", "+00:00"))
        timestamp = timestamp.astimezone(timezone.utc)
    except (ValueError, OverflowError) as exc:
        raise ParseError("invalid timestamp") from exc
    source = _text(record["source_ip"], "source_ip")
    try:
        if "%" in source:
            raise ValueError("zone identifiers are unsupported")
        address = ipaddress.ip_address(source)
    except ValueError as exc:
        raise ParseError("source_ip must be an IPv4 or IPv6 address without a zone identifier") from exc
    if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped:
        address = address.ipv4_mapped
    outcome = _text(record["outcome"], "outcome")
    method = _text(record.get("method", "password"), "method")
    if outcome not in {"failure", "success"}:
        raise ParseError("outcome must be failure or success")
    if method not in METHODS:
        raise ParseError("unsupported authentication method")
    mfa_used = record.get("mfa_used")
    if mfa_used is not None and type(mfa_used) is not bool:
        raise ParseError("mfa_used must be true, false, or null")
    identity_type = record.get("identity_type")
    if identity_type is not None and identity_type not in ("Root", "IAMUser"):
        raise ParseError("identity_type must be Root, IAMUser, or null")
    if method != "aws-console" and identity_type is not None:
        raise ParseError("identity_type is supported only for aws-console events")
    return Event(timestamp, _text(record["host"], "host"), _text(record["user"], "user"),
                 str(address), outcome, method, line, mfa_used, identity_type, record_index)


def load_events(path: Path, format_name: str = "auto", max_events: int = MAX_EVENTS) -> LoadResult:
    """Read bounded lines, retain up to 100 diagnostics, then sort by UTC and line."""
    if max_events < 1:
        raise ValueError("max_events must be positive")
    if format_name == "cloudtrail":
        from .cloudtrail import load_cloudtrail
        return load_cloudtrail(path, max_events)
    result = LoadResult()
    with path.open(encoding="utf-8-sig") as stream:
        while text := stream.readline(MAX_LINE_LENGTH + 1):
            result.total_lines += 1
            if len(text) > MAX_LINE_LENGTH:
                while not text.endswith("\n"):
                    text = stream.readline(MAX_LINE_LENGTH + 1)
                    if not text:
                        break
                result.reject(result.total_lines, "line exceeds 65536 characters")
                continue
            if not text.strip():
                continue
            try:
                event = parse_line(text, result.total_lines, format_name)
            except ParseError as exc:
                result.reject(result.total_lines, str(exc))
                continue
            if len(result.events) >= max_events:
                raise ValueError(f"event limit ({max_events}) exceeded; split the input file")
            result.events.append(event)
    result.events.sort(key=lambda event: (event.timestamp, event.line))
    return result
