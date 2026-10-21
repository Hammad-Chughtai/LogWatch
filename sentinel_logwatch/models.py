"""Shared data structures; input timestamps are normalized to UTC."""

from dataclasses import asdict, dataclass, field
from datetime import datetime
from typing import Any


def iso(timestamp: datetime) -> str:
    return timestamp.isoformat().replace("+00:00", "Z")


@dataclass(frozen=True)
class Event:
    timestamp: datetime
    host: str
    user: str
    source_ip: str
    outcome: str
    method: str
    line: int
    mfa_used: bool | None = None
    identity_type: str | None = None
    record_index: int | None = None

    def evidence(self) -> dict[str, Any]:
        return {"line": self.line if self.record_index is None else None,
                "location": (f"line {self.line}" if self.record_index is None else
                             "event" if self.record_index == -1 else f"Records[{self.record_index}]"),
                "timestamp": iso(self.timestamp), "source_ip": self.source_ip,
                "user": self.user, "outcome": self.outcome, "method": self.method,
                "mfa_used": self.mfa_used, "identity_type": self.identity_type}


@dataclass(frozen=True)
class Config:
    window_seconds: int = 300
    brute_force_threshold: int = 5
    spray_user_threshold: int = 5
    success_failure_threshold: int = 5
    distributed_failure_threshold: int = 10
    distributed_source_threshold: int = 3

    def __post_init__(self) -> None:
        for name, value in asdict(self).items():
            if type(value) is not int or value < 1:
                raise ValueError(f"{name} must be a positive integer")
            maximum = 86_400 if name == "window_seconds" else 200_000
            if value > maximum:
                raise ValueError(f"{name} must be at most {maximum}")


@dataclass
class LoadResult:
    events: list[Event] = field(default_factory=list)
    total_lines: int = 0
    rejected_lines: int = 0
    diagnostics: list[dict[str, Any]] = field(default_factory=list)
    reference_kind: str = "line"
    ignored_records: int = 0

    def reject(self, line: int, reason: str, location: str | None = None) -> None:
        self.rejected_lines += 1
        if len(self.diagnostics) < 100:
            self.diagnostics.append({"line": line if location is None else None,
                                     "location": location or f"line {line}", "reason": reason})
