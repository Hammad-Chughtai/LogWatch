"""Sliding-window rules with scoped correlation and alert cooldowns."""

import hashlib
from collections import Counter, defaultdict, deque
from dataclasses import asdict
from datetime import datetime, timedelta, timezone
from itertools import islice
from typing import Any

from . import __version__
from .models import Config, Event, LoadResult, iso

RULES = {
    "LW001": {
        "title": "Repeated password failures", "severity": "medium", "technique": "T1110.001",
        "guidance": "Check whether the account owner or an automation task caused the failures. Review adjacent authentication events and existing access controls before responding.",
    },
    "LW002": {
        "title": "Multi-account guessing (spray-like)", "severity": "medium", "technique": "T1110.003",
        "guidance": "Review the source and targeted accounts. A shared NAT, vulnerability scanner, or misconfigured service can produce this pattern. Logs do not reveal whether a shared password was tried.",
    },
    "LW003": {
        "title": "Successful login after repeated failures", "severity": "high", "technique": "T1110.001",
        "guidance": "Validate the login with the account owner and inspect session activity on the host. This correlation is a triage signal and does not establish account compromise.",
    },
    "LW004": {
        "title": "Distributed account guessing", "severity": "high", "technique": "T1110.001",
        "guidance": "Review failures across the listed source addresses for this account. Distributed activity can evade per-IP thresholds; proxies, VPN rotation, and stale clients can also produce this pattern.",
    },
    "LW005": {
        "title": "AWS root console login without recorded MFA", "severity": "high", "technique": "AWS root / MFA",
        "guidance": "CloudTrail explicitly records a successful Root ConsoleLogin with MFAUsed=No. Validate whether this root session was authorized and review root-account MFA controls and subsequent activity.",
    },
}
EVIDENCE_LIMIT = 20
USER_SAMPLE_LIMIT = 20


def _sample(events: deque[Event]) -> list[dict[str, Any]]:
    if len(events) <= EVIDENCE_LIMIT:
        return [event.evidence() for event in events]
    first = list(islice(events, EVIDENCE_LIMIT // 2))
    last = list(reversed(list(islice(reversed(events), EVIDENCE_LIMIT // 2))))
    return [event.evidence() for event in first + last]


def detect(events: list[Event], config: Config) -> list[dict[str, Any]]:
    """Sort events; correlate by host/source/account, never across hosts.

    Window endpoints are inclusive. Equal timestamps follow source line order.
    Each rule/scope emits at most once per window; success correlation resets
    account failure history after each success, including public-key logins.
    """
    accounts: dict[tuple, deque[Event]] = defaultdict(deque)
    sources: dict[tuple, deque[Event]] = defaultdict(deque)
    source_users: dict[tuple, Counter] = defaultdict(Counter)
    distributed: dict[tuple, deque[Event]] = defaultdict(deque)
    distributed_sources: dict[tuple, Counter] = defaultdict(Counter)
    last_alert: dict[tuple, datetime] = {}
    alerts: list[dict[str, Any]] = []
    window = timedelta(seconds=config.window_seconds)

    def emit(rule_id: str, event: Event, scope: tuple, history: deque[Event], users: Any, addresses: Any = None) -> None:
        key = (rule_id, *scope)
        previous = last_alert.get(key)
        if previous is not None and event.timestamp - previous < window:
            return
        last_alert[key] = event.timestamp
        rule = RULES[rule_id]
        addresses = addresses if addresses is not None else {event.source_ip}
        evidence = _sample(history)
        if event.outcome == "success":
            if len(evidence) == EVIDENCE_LIMIT:
                evidence = evidence[:9] + evidence[-10:]
            evidence.append(event.evidence())
        identity = repr((rule_id, scope, iso(event.timestamp), event.line)).encode()
        alerts.append({
            "id": hashlib.sha256(identity).hexdigest()[:12], "rule_id": rule_id, **rule,
            "source_ip": event.source_ip, "host": event.host,
            "source_ips": list(islice(sorted(addresses), USER_SAMPLE_LIMIT)), "source_count": len(addresses),
            "users": list(islice(sorted(users), USER_SAMPLE_LIMIT)), "user_count": len(users),
            "failure_count": len(history), "first_seen": iso(history[0].timestamp if history else event.timestamp),
            "last_seen": iso(event.timestamp), "evidence": evidence,
            "evidence_sampled": len(history) + (event.outcome == "success") > len(evidence),
        })

    for event in sorted(events, key=lambda item: (item.timestamp, item.line)):
        account_key = (event.host, event.source_ip, event.user)
        history = accounts[account_key]
        distributed_key = (event.host, event.user)
        try:
            cutoff = event.timestamp - window
        except OverflowError:
            cutoff = datetime.min.replace(tzinfo=timezone.utc)
        while history and history[0].timestamp < cutoff:
            history.popleft()
        if event.outcome == "success":
            if event.method == "aws-console" and event.identity_type == "Root" and event.mfa_used is False:
                emit("LW005", event, account_key, deque(), {event.user})
            if len(history) >= config.success_failure_threshold:
                emit("LW003", event, account_key, history, {event.user})
            history.clear()
            distributed.pop(distributed_key, None)
            distributed_sources.pop(distributed_key, None)
            continue
        if event.method == "publickey":
            continue
        history.append(event)
        if len(history) >= config.brute_force_threshold:
            emit("LW001", event, account_key, history, {event.user})

        source_key = (event.host, event.source_ip)
        source_history, counts = sources[source_key], source_users[source_key]
        while source_history and source_history[0].timestamp < cutoff:
            expired = source_history.popleft()
            counts[expired.user] -= 1
            if counts[expired.user] == 0:
                del counts[expired.user]
        source_history.append(event)
        counts[event.user] += 1
        if len(counts) >= config.spray_user_threshold:
            emit("LW002", event, source_key, source_history, counts)

        distributed_history = distributed[distributed_key]
        address_counts = distributed_sources[distributed_key]
        while distributed_history and distributed_history[0].timestamp < cutoff:
            expired = distributed_history.popleft()
            address_counts[expired.source_ip] -= 1
            if address_counts[expired.source_ip] == 0:
                del address_counts[expired.source_ip]
        distributed_history.append(event)
        address_counts[event.source_ip] += 1
        if len(distributed_history) >= config.distributed_failure_threshold and len(address_counts) >= config.distributed_source_threshold:
            emit("LW004", event, distributed_key, distributed_history, {event.user}, address_counts)

    return sorted(alerts, key=lambda alert: (alert["last_seen"], alert["rule_id"], alert["id"]))


def build_report(loaded: LoadResult, config: Config, source_name: str) -> dict[str, Any]:
    events = loaded.events
    failures = [event for event in events if event.outcome == "failure"]
    counts = Counter(event.source_ip for event in failures)
    alerts = detect(events, config)
    return {
        "schema_version": 1, "tool_version": __version__, "source": source_name,
        "config": asdict(config),
        "reference_kind": loaded.reference_kind,
        "summary": {"total_lines": loaded.total_lines if loaded.reference_kind == "line" else None,
                    "total_records": loaded.total_lines, "ignored_records": loaded.ignored_records,
                    "parsed_events": len(events), "rejected_records": loaded.rejected_lines,
                    "rejected_lines": loaded.rejected_lines if loaded.reference_kind == "line" else None, "failures": len(failures),
                    "successes": len(events) - len(failures),
                    "source_count": len({event.source_ip for event in events}),
                    "host_count": len({event.host for event in events}),
                    "alerts": len(alerts), "high": sum(a["severity"] == "high" for a in alerts),
                    "medium": sum(a["severity"] == "medium" for a in alerts)},
        "top_sources": [{"source_ip": source, "failures": count}
                        for source, count in sorted(counts.items(), key=lambda item: (-item[1], item[0]))[:10]],
        "alerts": alerts, "diagnostics": loaded.diagnostics,
        "diagnostics_truncated": loaded.rejected_lines > len(loaded.diagnostics),
    }
