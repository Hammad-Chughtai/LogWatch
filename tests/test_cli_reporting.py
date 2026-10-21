import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path

from sentinel_logwatch.cli import load_config, main
from sentinel_logwatch.detector import build_report
from sentinel_logwatch.models import Config
from sentinel_logwatch.parsers import load_events
from sentinel_logwatch.reporting import render_html
from tests.test_parsers import record


class CliTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.input = self.root / "auth.jsonl"
        self.input.write_text("\n".join(record(timestamp=f"2026-01-15T09:00:0{i}Z") for i in range(5)) + "\n" + record(timestamp="2026-01-15T09:00:06Z", outcome="success") + "\n", encoding="utf-8")

    def run_cli(self, *args):
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = main(["analyze", str(self.input), *map(str, args)])
        return code, out.getvalue(), err.getvalue()

    def test_writes_valid_json_and_html(self):
        code, out, _ = self.run_cli("--json", self.root / "report.json", "--html", self.root / "report.html")
        self.assertEqual(code, 0)
        data = json.loads((self.root / "report.json").read_text(encoding="utf-8"))
        self.assertEqual(data["summary"]["high"], 1)
        self.assertIn("6 events", out)
        self.assertIn("Content-Security-Policy", (self.root / "report.html").read_text(encoding="utf-8"))

    def test_fail_on_is_opt_in_and_still_writes_reports(self):
        self.assertEqual(self.run_cli()[0], 0)
        self.assertEqual(self.run_cli("--fail-on", "high", "--json", self.root / "report.json")[0], 1)
        self.assertTrue((self.root / "report.json").exists())

    def test_medium_threshold_catches_medium_without_high(self):
        self.input.write_text((record() + "\n") * 5, encoding="utf-8")
        self.assertEqual(self.run_cli("--fail-on", "high")[0], 0)
        self.assertEqual(self.run_cli("--fail-on", "medium")[0], 1)

    def test_strict_rejects_without_writing_or_replacing_report(self):
        self.input.write_text(self.input.read_text(encoding="utf-8") + "bad input\n", encoding="utf-8")
        output = self.root / "report.json"
        output.write_text("keep me", encoding="utf-8")
        code, _, err = self.run_cli("--strict", "--json", output)
        self.assertEqual(code, 2)
        self.assertIn("strict mode", err)
        self.assertEqual(output.read_text(encoding="utf-8"), "keep me")

    def test_partial_input_has_warning_and_diagnostics(self):
        self.input.write_text(self.input.read_text(encoding="utf-8") + "bad input\n", encoding="utf-8")
        code, _, err = self.run_cli("--json", self.root / "report.json")
        data = json.loads((self.root / "report.json").read_text(encoding="utf-8"))
        self.assertEqual((code, data["summary"]["rejected_lines"]), (0, 1))
        self.assertIn("partial input", err)

    def test_input_and_config_cannot_be_overwritten(self):
        original = self.input.read_bytes()
        self.assertEqual(self.run_cli("--json", self.input)[0], 2)
        self.assertEqual(self.input.read_bytes(), original)
        config = self.root / "config.toml"
        config.write_text("[detection]\n", encoding="utf-8")
        self.assertEqual(self.run_cli("--config", config, "--html", config)[0], 2)

    def test_output_paths_must_be_distinct(self):
        output = self.root / "report.html"
        self.assertEqual(self.run_cli("--json", output, "--html", output)[0], 2)
        self.assertFalse(output.exists())

    def test_empty_invalid_and_missing_input_fail_cleanly(self):
        for content in ["", "unsupported\n"]:
            self.input.write_text(content, encoding="utf-8")
            self.assertEqual(self.run_cli()[0], 2)
        self.input.unlink()
        self.assertEqual(self.run_cli()[0], 2)

    def test_bad_config_is_not_silently_ignored(self):
        path = self.root / "config.toml"
        for content in ["[detection]\ntyop = 3", "[other]\nx = 3", "[detection]\nwindow_seconds = true", "not TOML"]:
            path.write_text(content, encoding="utf-8")
            self.assertEqual(self.run_cli("--config", path)[0], 2)

    def test_configuration_changes_detection(self):
        path = self.root / "config.toml"
        path.write_text("[detection]\nbrute_force_threshold = 10\nsuccess_failure_threshold = 10\n", encoding="utf-8")
        self.assertEqual(load_config(path).brute_force_threshold, 10)
        self.assertIn("Alerts: 0", self.run_cli("--config", path)[1])

    def test_output_error_does_not_leave_temporary_files(self):
        before = set(self.root.iterdir())
        self.assertEqual(self.run_cli("--html", self.root / "missing" / "report.html")[0], 2)
        self.assertEqual(before, set(self.root.iterdir()))

    def test_html_escapes_log_values_and_has_no_external_assets(self):
        malicious = '<script>alert("x")</script>'
        self.input.write_text((record(user=malicious, host='host<img src=x onerror=alert(1)>') + "\n") * 5, encoding="utf-8")
        html = render_html(build_report(load_events(self.input), Config(), malicious))
        self.assertNotIn("<script>", html)
        self.assertNotIn("<img", html)
        self.assertIn("&lt;script&gt;", html)
        self.assertIn("default-src 'none'", html)
        self.assertNotIn("https://", html)

    def test_demo_formats_produce_equivalent_alerts(self):
        project = Path(__file__).resolve().parents[1]
        json_data = load_events(project / "examples" / "auth.jsonl")
        ssh_data = load_events(project / "examples" / "openssh.log")
        first = build_report(json_data, Config(), "demo")
        second = build_report(ssh_data, Config(), "demo")
        self.assertEqual(first, second)
        self.assertEqual([a["rule_id"] for a in first["alerts"]], ["LW001", "LW003", "LW002"])
