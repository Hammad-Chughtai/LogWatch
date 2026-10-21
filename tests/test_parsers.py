import json
import tempfile
import unittest
from pathlib import Path

from sentinel_logwatch.parsers import MAX_LINE_LENGTH, ParseError, load_events, parse_line


def record(**changes):
    data = {"timestamp": "2026-01-15T09:00:00Z", "host": "web-01", "user": "alice",
            "source_ip": "203.0.113.10", "outcome": "failure", "method": "password"}
    return json.dumps(data | changes)


class ParserTests(unittest.TestCase):
    def test_jsonl_normalizes_offset(self):
        event = parse_line(record(timestamp="2026-01-15T10:00:00+01:00"), 8)
        self.assertEqual(event.timestamp.hour, 9)
        self.assertEqual(event.line, 8)

    def test_ipv6_is_canonical_and_mapped_ipv4_collapses(self):
        self.assertEqual(parse_line(record(source_ip="2001:0db8::1"), 1).source_ip, "2001:db8::1")
        self.assertEqual(parse_line(record(source_ip="::ffff:203.0.113.10"), 1).source_ip, "203.0.113.10")

    def test_openssh_password_and_publickey(self):
        for prefix, outcome, method in [("Failed password for invalid user", "failure", "password"),
                                        ("Accepted publickey for", "success", "publickey")]:
            text = f"2026-01-15T09:00:00Z web-01 sshd[42]: {prefix} alice from 2001:db8::1 port 1234 ssh2"
            event = parse_line(text, 4)
            self.assertEqual((event.outcome, event.method, event.user), (outcome, method, "alice"))

    def test_openssh_session_and_keyboard_interactive(self):
        text = "2026-01-15T09:00:00+00:00 web-01 sshd-session[42]: Failed keyboard-interactive/pam for alice from 192.0.2.1 port 22 ssh2"
        self.assertEqual(parse_line(text, 1).method, "keyboard-interactive")

    def test_invalid_fields_are_rejected(self):
        for changes in [{"timestamp": "2026-01-15T09:00:00"}, {"timestamp": "2026-02-30T09:00:00Z"},
                        {"source_ip": "999.1.1.1"}, {"source_ip": "fe80::1%eth0"}, {"user": ""},
                        {"user": "a\x1bb"}, {"host": []}, {"outcome": "maybe"}, {"method": True},
                        {"secret": "never retain"}, {"user": "x" * 256}]:
            with self.subTest(changes=changes), self.assertRaises(ParseError):
                parse_line(record(**changes), 1)

    def test_duplicate_keys_and_bad_shapes_are_rejected(self):
        for text in ['{"host":"a","host":"b"}', '[]', 'null', '{', '{"timestamp":1}']:
            with self.subTest(text=text), self.assertRaises(ParseError):
                parse_line(text, 1, "jsonl")

    def test_legacy_timestamp_is_not_guessed(self):
        with self.assertRaises(ParseError):
            parse_line("Jan 15 09:00:00 web sshd[1]: Failed password for root from 192.0.2.1 port 22 ssh2", 1)

    def test_loader_sorts_and_preserves_original_lines(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "auth.jsonl"
            path.write_text(record(timestamp="2026-01-15T09:01:00Z") + "\n\nBAD\n" + record() + "\n", encoding="utf-8-sig")
            loaded = load_events(path)
            self.assertEqual([e.line for e in loaded.events], [4, 1])
            self.assertEqual((loaded.total_lines, loaded.rejected_lines), (4, 1))
            self.assertEqual(loaded.diagnostics[0]["line"], 3)

    def test_oversized_lines_do_not_desynchronize_line_numbers(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "auth.log"
            path.write_text("x" * (MAX_LINE_LENGTH * 2) + "\n" + record() + "\n", encoding="utf-8")
            loaded = load_events(path)
            self.assertEqual((loaded.total_lines, loaded.rejected_lines, loaded.events[0].line), (2, 1, 2))

    def test_diagnostics_are_bounded_without_raw_log_data(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "auth.log"
            path.write_text("do-not-retain-this\n" * 110, encoding="utf-8")
            loaded = load_events(path)
            self.assertEqual((loaded.rejected_lines, len(loaded.diagnostics)), (110, 100))
            self.assertNotIn("do-not-retain-this", str(loaded.diagnostics))

    def test_event_limit_rejects_partial_analysis(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "auth.jsonl"
            path.write_text((record() + "\n") * 2, encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "event limit"):
                load_events(path, max_events=1)
