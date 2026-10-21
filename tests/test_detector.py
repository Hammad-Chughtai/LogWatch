import unittest
from datetime import datetime, timedelta, timezone

from sentinel_logwatch.detector import detect
from sentinel_logwatch.models import Config, Event

BASE = datetime(2026, 1, 15, 9, tzinfo=timezone.utc)


def event(second, *, user="alice", host="web-01", source="203.0.113.10", outcome="failure", method="password", line=None):
    return Event(BASE + timedelta(seconds=second), host, user, source, outcome, method, second + 1 if line is None else line)


class DetectorTests(unittest.TestCase):
    def test_brute_force_at_threshold_with_one_alert_per_window(self):
        alerts = detect([event(i) for i in range(15)], Config())
        self.assertEqual([a["rule_id"] for a in alerts], ["LW001"])
        self.assertEqual(alerts[0]["failure_count"], 5)
        self.assertEqual(alerts[0]["evidence"][-1]["line"], 5)

    def test_window_endpoints_are_inclusive(self):
        self.assertEqual(len(detect([event(0), event(300)], Config(brute_force_threshold=2))), 1)
        self.assertEqual(detect([event(0), event(301)], Config(brute_force_threshold=2)), [])

    def test_below_threshold_is_quiet(self):
        self.assertEqual(detect([event(i) for i in range(4)], Config()), [])

    def test_hosts_sources_and_accounts_do_not_mix(self):
        for field, value in [("host", "db-01"), ("source", "192.0.2.1"), ("user", "bob")]:
            with self.subTest(field=field):
                events = [event(i) for i in range(4)] + [event(4, **{field: value})]
                self.assertEqual(detect(events, Config()), [])

    def test_spray_like_pattern_counts_distinct_accounts(self):
        alerts = detect([event(i, user=f"user-{i}") for i in range(6)], Config())
        self.assertEqual([a["rule_id"] for a in alerts], ["LW002"])
        self.assertEqual(alerts[0]["user_count"], 5)

    def test_expired_spray_accounts_are_removed(self):
        events = [event(0, user="old")] + [event(301 + i, user=f"new-{i}") for i in range(4)]
        self.assertEqual(detect(events, Config()), [])

    def test_success_requires_same_host_source_and_account(self):
        failures = [event(i) for i in range(5)]
        for field, value in [("host", "db-01"), ("source", "192.0.2.1"), ("user", "bob")]:
            alerts = detect(failures + [event(6, outcome="success", **{field: value})], Config())
            self.assertNotIn("LW003", [a["rule_id"] for a in alerts])

    def test_success_includes_evidence_and_resets_history(self):
        events = [event(i) for i in range(5)] + [event(6, outcome="success", method="publickey"), event(400, outcome="success")]
        alerts = detect(events, Config())
        success = [a for a in alerts if a["rule_id"] == "LW003"]
        self.assertEqual(len(success), 1)
        self.assertEqual(success[0]["evidence"][-1]["outcome"], "success")
        self.assertEqual(success[0]["evidence"][-1]["method"], "publickey")

    def test_a_success_cannot_be_explained_by_later_failures(self):
        events = [event(0, outcome="success", line=1)] + [event(0, line=i + 2) for i in range(5)]
        self.assertNotIn("LW003", [a["rule_id"] for a in detect(events, Config())])

    def test_publickey_failures_do_not_trigger_password_rules(self):
        events = [event(i, method="publickey") for i in range(10)] + [event(11, outcome="success")]
        self.assertEqual(detect(events, Config()), [])

    def test_shuffled_input_produces_identical_alerts(self):
        events = [event(i) for i in range(5)] + [event(6, outcome="success")]
        self.assertEqual(detect(events, Config()), detect(list(reversed(events)), Config()))

    def test_cooldown_expires_and_old_failures_are_pruned(self):
        events = [event(i) for i in range(5)] + [event(400 + i) for i in range(5)]
        alerts = detect(events, Config())
        self.assertEqual(len(alerts), 2)
        self.assertTrue(all(a["failure_count"] == 5 for a in alerts))

    def test_evidence_sample_includes_latest_failure_and_success(self):
        events = [event(i) for i in range(50)] + [event(51, outcome="success")]
        alert = [a for a in detect(events, Config()) if a["rule_id"] == "LW003"][0]
        self.assertEqual(len(alert["evidence"]), 20)
        self.assertEqual([e["line"] for e in alert["evidence"][-2:]], [50, 52])
        self.assertTrue(alert["evidence_sampled"])

    def test_minimum_datetime_does_not_overflow(self):
        earliest = Event(datetime.min.replace(tzinfo=timezone.utc), "h", "u", "192.0.2.1", "failure", "password", 1)
        self.assertEqual(detect([earliest], Config()), [])

    def test_config_rejects_booleans_zero_and_unbounded_values(self):
        for value in [True, 0, -1, "5", 1.5, 200_001]:
            with self.subTest(value=value), self.assertRaises(ValueError):
                Config(brute_force_threshold=value)
        with self.assertRaises(ValueError):
            Config(window_seconds=86_401)

    def test_distributed_guessing_combines_multiple_sources(self):
        events = [event(i, source=f"192.0.2.{i % 4 + 1}") for i in range(10)]
        alerts = detect(events, Config())
        self.assertEqual([a["rule_id"] for a in alerts], ["LW004"])
        self.assertEqual(alerts[0]["source_count"], 4)
        self.assertEqual(alerts[0]["failure_count"], 10)
        self.assertEqual({e["source_ip"] for e in alerts[0]["evidence"]}, {f"192.0.2.{i}" for i in range(1, 5)})

    def test_distributed_rule_requires_both_thresholds(self):
        events = [event(i, source=f"192.0.2.{i % 2 + 1}") for i in range(10)]
        self.assertNotIn("LW004", [a["rule_id"] for a in detect(events, Config())])

    def test_distributed_rule_does_not_mix_hosts_or_users(self):
        for field in ["host", "user"]:
            events = [event(i, source=f"192.0.2.{i % 4 + 1}", **{field: f"scope-{i % 2}"}) for i in range(10)]
            self.assertNotIn("LW004", [a["rule_id"] for a in detect(events, Config())])

    def test_distributed_expiry_and_success_reset(self):
        failures = [event(i, source=f"192.0.2.{i % 4 + 1}") for i in range(9)]
        self.assertNotIn("LW004", [a["rule_id"] for a in detect(failures + [event(400, source="192.0.2.5")], Config())])
        events = failures + [event(10, outcome="success"), event(11, source="192.0.2.5")]
        self.assertNotIn("LW004", [a["rule_id"] for a in detect(events, Config())])
