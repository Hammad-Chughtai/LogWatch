"""Read downloaded CloudTrail JSON without credentials or AWS API access."""

import json
import re
from pathlib import Path

from .models import LoadResult
from .parsers import MAX_EVENTS, ParseError, _unique_keys, normalize_record

MAX_CLOUDTRAIL_BYTES = 32 * 1024 * 1024
FEDERATED_TYPES = {"AssumedRole", "FederatedUser", "IdentityCenterUser", "AWSService"}


def load_cloudtrail(path: Path, max_events: int = MAX_EVENTS) -> LoadResult:
    """Accept a Records envelope or a single CloudTrail event.

    Evidence references zero-based Records array positions, not physical lines.
    Non-console events and explicitly federated identities are counted as ignored.
    """
    with path.open("rb") as stream:
        raw = stream.read(MAX_CLOUDTRAIL_BYTES + 1)
    if len(raw) > MAX_CLOUDTRAIL_BYTES:
        raise ValueError("CloudTrail JSON exceeds 32 MiB; split or filter the export")
    try:
        document = json.loads(raw.decode("utf-8-sig"), object_pairs_hook=_unique_keys)
    except (json.JSONDecodeError, RecursionError) as exc:
        raise ValueError("invalid CloudTrail JSON document") from exc
    if not isinstance(document, dict):
        raise ValueError("CloudTrail input must be a Records envelope or one event object")
    records = document.get("Records", [document])
    if not isinstance(records, list):
        raise ValueError("CloudTrail Records must be an array")
    if len(records) > max_events:
        raise ValueError(f"CloudTrail record limit ({max_events}) exceeded; split the export")
    result = LoadResult(total_lines=len(records), reference_kind="record")
    for index, record in enumerate(records):
        location = f"Records[{index}]" if "Records" in document else "event"
        try:
            if not isinstance(record, dict):
                raise ParseError("CloudTrail record must be an object")
            if record.get("eventSource") != "signin.amazonaws.com" or record.get("eventName") != "ConsoleLogin":
                result.ignored_records += 1
                continue
            identity = record.get("userIdentity")
            if not isinstance(identity, dict):
                raise ParseError("ConsoleLogin userIdentity must be an object")
            kind = identity.get("type")
            if isinstance(kind, str) and kind in FEDERATED_TYPES:
                result.ignored_records += 1
                continue
            if kind not in ("IAMUser", "Root"):
                raise ParseError("unsupported ConsoleLogin identity type")
            account = identity.get("accountId")
            if not isinstance(account, str) or not re.fullmatch(r"\d{12}", account, flags=re.ASCII):
                raise ParseError("ConsoleLogin requires a 12-digit accountId")
            response = record.get("responseElements")
            if not isinstance(response, dict) or response.get("ConsoleLogin") not in ("Success", "Failure"):
                raise ParseError("ConsoleLogin response must be Success or Failure")
            extra = record.get("additionalEventData", {})
            if not isinstance(extra, dict) or extra.get("MFAUsed") not in ("Yes", "No", None):
                raise ParseError("MFAUsed must be Yes, No, or absent")
            user = "root" if kind == "Root" else identity.get("userName")
            if user == "HIDDEN_DUE_TO_SECURITY_REASONS":
                raise ParseError("CloudTrail obscured the account name; reliable correlation is unavailable")
            mfa = extra.get("MFAUsed")
            normalized = {"timestamp": record.get("eventTime"), "host": f"aws:{account}",
                          "user": user, "source_ip": record.get("sourceIPAddress"),
                          "outcome": "success" if response["ConsoleLogin"] == "Success" else "failure",
                          "method": "aws-console", "identity_type": kind,
                          "mfa_used": None if mfa is None else mfa == "Yes"}
            result.events.append(normalize_record(normalized, index + 1, record_index=index if "Records" in document else -1))
        except ParseError as exc:
            result.reject(index + 1, str(exc), location)
    result.events.sort(key=lambda event: (event.timestamp, event.line))
    return result
