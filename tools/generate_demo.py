"""Generate local synthetic fixtures. This script does not contact any host."""

import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
BASE = datetime(2026, 1, 15, 9, tzinfo=timezone.utc)


def main():
    events = []

    def add(seconds, user, source_ip, outcome="failure", host="web-01", method="password"):
        events.append({"timestamp": (BASE + timedelta(seconds=seconds)).isoformat().replace("+00:00", "Z"),
                       "host": host, "user": user, "source_ip": source_ip, "outcome": outcome, "method": method})

    add(0, "alice", "192.0.2.10", "success", method="publickey")
    add(10, "bob", "192.0.2.20")
    add(20, "bob", "192.0.2.20", "success")
    for second in range(60, 120, 10):
        add(second, "admin", "203.0.113.50")
    add(130, "admin", "203.0.113.50", "success")
    for index, user in enumerate(["alice", "bob", "carol", "dave", "erin", "frank"]):
        add(180 + index * 10, user, "198.51.100.23", host="vpn-01")
    add(300, "deploy", "2001:db8::8", "success", method="publickey")
    add(360, "alice", "192.0.2.10", "success", method="publickey")

    directory = ROOT / "examples"
    directory.mkdir(exist_ok=True)
    (directory / "auth.jsonl").write_text("".join(json.dumps(event, sort_keys=True) + "\n" for event in events), encoding="utf-8", newline="\n")
    ssh = []
    for index, event in enumerate(events):
        status = "Failed" if event["outcome"] == "failure" else "Accepted"
        ssh.append(f"{event['timestamp']} {event['host']} sshd[{1000 + index}]: {status} {event['method']} for {event['user']} from {event['source_ip']} port {40000 + index} ssh2\n")
    (directory / "openssh.log").write_text("".join(ssh), encoding="utf-8", newline="\n")
    print(f"Generated {len(events)} synthetic authentication records in each format.")

    cloud = []

    def console(seconds, user, source, outcome="Failure", mfa="No", kind="IAMUser"):
        cloud.append({"eventVersion": "1.08", "eventSource": "signin.amazonaws.com", "eventName": "ConsoleLogin",
                      "eventTime": (BASE + timedelta(seconds=seconds)).isoformat().replace("+00:00", "Z"),
                      "userIdentity": {"type": kind, "accountId": "000000000000", "userName": user},
                      "sourceIPAddress": source, "responseElements": {"ConsoleLogin": outcome},
                      "additionalEventData": {"MFAUsed": mfa}, "awsRegion": "us-east-1"})

    console(0, "analyst", "192.0.2.40", "Success", "Yes")
    for index in range(10):
        console(20 + index * 10, "deploy-admin", f"198.51.100.{100 + index % 4}")
    console(140, "root", "203.0.113.99", "Success", "No", "Root")
    console(200, "root", "203.0.113.99", "Success", "Yes", "Root")
    console(220, "federated-session", "192.0.2.40", "Success", "No", "AssumedRole")
    cloud.append({"eventName": "ListBuckets", "eventSource": "s3.amazonaws.com"})
    (directory / "cloudtrail.json").write_text(json.dumps({"Records": cloud}, indent=2) + "\n", encoding="utf-8", newline="\n")
    modern = list(events)
    for item in cloud[:13]:
        identity = item["userIdentity"]
        modern.append({"timestamp": item["eventTime"], "host": "aws:000000000000", "user": identity["userName"],
                       "source_ip": item["sourceIPAddress"], "outcome": "success" if item["responseElements"]["ConsoleLogin"] == "Success" else "failure",
                       "method": "aws-console", "identity_type": identity["type"],
                       "mfa_used": item["additionalEventData"]["MFAUsed"] == "Yes"})
    modern.sort(key=lambda item: item["timestamp"])
    (directory / "modern-auth.jsonl").write_text("".join(json.dumps(item, sort_keys=True) + "\n" for item in modern), encoding="utf-8", newline="\n")
    print("Generated CloudTrail and combined cloud/SSH authentication fixtures.")


if __name__ == "__main__":
    main()
