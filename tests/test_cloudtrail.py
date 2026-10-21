import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from logwatch.cli import main
from logwatch.cloudtrail import load_cloudtrail
from logwatch.detector import build_report, detect
from logwatch.models import Config


def console(**changes):
    return {"eventSource": "signin.amazonaws.com", "eventName": "ConsoleLogin",
            "eventTime": "2026-01-15T09:00:00Z", "sourceIPAddress": "203.0.113.1",
            "userIdentity": {"type": "Root", "accountId": "000000000000"},
            "responseElements": {"ConsoleLogin": "Success"},
            "additionalEventData": {"MFAUsed": "No"}} | changes


class CloudTrailTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name) / "cloudtrail.json"

    def load(self, records):
        self.path.write_text(json.dumps({"Records": records}), encoding="utf-8")
        return load_cloudtrail(self.path)

    def test_root_without_mfa_has_explicit_evidence(self):
        loaded = self.load([console()])
        alerts = detect(loaded.events, Config())
        self.assertEqual([a["rule_id"] for a in alerts], ["LW005"])
        self.assertEqual(alerts[0]["failure_count"], 0)
        evidence = alerts[0]["evidence"][0]
        self.assertIs(evidence["mfa_used"], False)
        self.assertEqual(evidence["identity_type"], "Root")
        self.assertEqual(evidence["location"], "Records[0]")
        self.assertIsNone(evidence["line"])
        self.assertEqual(alerts[0]["host"], "aws:000000000000")

    def test_mfa_required_signal_is_narrow(self):
        iam = {"type": "IAMUser", "accountId": "000000000000", "userName": "admin"}
        cases = [console(additionalEventData={"MFAUsed": "Yes"}), console(additionalEventData={}),
                 console(responseElements={"ConsoleLogin": "Failure"}), console(userIdentity=iam)]
        for record in cases:
            with self.subTest(record=record):
                self.assertNotIn("LW005", [a["rule_id"] for a in detect(self.load([record]).events, Config())])

    def test_federated_mfa_no_is_ignored_without_guessing_upstream_mfa(self):
        for kind in ["AssumedRole", "FederatedUser", "IdentityCenterUser"]:
            loaded = self.load([console(userIdentity={"type": kind})])
            self.assertEqual((len(loaded.events), loaded.ignored_records, loaded.rejected_lines), (0, 1, 0))

    def test_unrelated_service_events_are_counted_as_ignored(self):
        loaded = self.load([console(), {"eventSource": "s3.amazonaws.com", "eventName": "ListBuckets"}])
        self.assertEqual((len(loaded.events), loaded.ignored_records), (1, 1))

    def test_malformed_console_records_have_indexed_diagnostics(self):
        cases = [None, console(userIdentity=None), console(userIdentity={"type": []}),
                 console(userIdentity={"type": "Root", "accountId": "bad"}),
                 console(responseElements=None), console(responseElements={"ConsoleLogin": []}),
                 console(additionalEventData={"MFAUsed": "maybe"}), console(sourceIPAddress="AWS Internal"),
                 console(eventTime=None)]
        for record in cases:
            with self.subTest(record=record):
                loaded = self.load([record])
                self.assertEqual((len(loaded.events), loaded.rejected_lines), (0, 1))
                self.assertEqual(loaded.diagnostics[0]["location"], "Records[0]")

    def test_hidden_usernames_are_not_correlated_as_one_account(self):
        identity = {"type": "IAMUser", "accountId": "000000000000", "userName": "HIDDEN_DUE_TO_SECURITY_REASONS"}
        loaded = self.load([console(userIdentity=identity)])
        self.assertEqual(loaded.rejected_lines, 1)
        self.assertIn("obscured", loaded.diagnostics[0]["reason"])

    def test_single_event_has_an_accurate_source_reference(self):
        self.path.write_text(json.dumps(console()), encoding="utf-8")
        self.assertEqual(load_cloudtrail(self.path).events[0].evidence()["location"], "event")

    def test_size_and_record_limits_fail_without_partial_analysis(self):
        self.path.write_text(json.dumps({"Records": [console(), console()]}), encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "record limit"):
            load_cloudtrail(self.path, max_events=1)
        with patch("logwatch.cloudtrail.MAX_CLOUDTRAIL_BYTES", 20):
            with self.assertRaisesRegex(ValueError, "32 MiB"):
                load_cloudtrail(self.path)

    def test_invalid_document_shapes_and_duplicate_keys_are_rejected(self):
        for text in ['[]', '{"Records":{}}', '{"Records":[],"Records":[]}', '{']:
            self.path.write_text(text, encoding="utf-8")
            with self.subTest(text=text), self.assertRaises(ValueError):
                load_cloudtrail(self.path)

    def test_summary_distinguishes_records_from_physical_lines(self):
        loaded = self.load([console(), None, {"eventSource": "s3.amazonaws.com"}])
        report = build_report(loaded, Config(), "cloudtrail.json")
        self.assertEqual(report["summary"]["total_records"], 3)
        self.assertIsNone(report["summary"]["total_lines"])
        self.assertEqual(report["summary"]["rejected_records"], 1)
        self.assertEqual(report["summary"]["ignored_records"], 1)

    def test_cli_cloudtrail_demo_works_without_aws_credentials(self):
        example = Path(__file__).resolve().parents[1] / "examples" / "cloudtrail.json"
        output = self.path.parent / "report.json"
        with contextlib.redirect_stdout(io.StringIO()):
            code = main(["analyze", str(example), "--format", "cloudtrail", "--strict", "--fail-on", "high", "--json", str(output)])
        self.assertEqual(code, 1)
        report = json.loads(output.read_text(encoding="utf-8"))
        self.assertEqual([a["rule_id"] for a in report["alerts"]], ["LW004", "LW005"])

    def test_cloud_account_ids_prevent_cross_account_aggregation(self):
        records = []
        for index in range(10):
            record = console(eventTime=f"2026-01-15T09:00:{index:02}Z", sourceIPAddress=f"192.0.2.{index % 4 + 1}",
                             responseElements={"ConsoleLogin": "Failure"})
            record["userIdentity"] = {"type": "IAMUser", "accountId": f"{index % 2:012}", "userName": "admin"}
            records.append(record)
        self.assertNotIn("LW004", [a["rule_id"] for a in detect(self.load(records).events, Config())])

    def test_combined_demo_contains_all_five_detection_rules(self):
        from logwatch.parsers import load_events
        example = Path(__file__).resolve().parents[1] / "examples" / "modern-auth.jsonl"
        self.assertEqual({a["rule_id"] for a in detect(load_events(example).events, Config())}, {f"LW00{i}" for i in range(1, 6)})
