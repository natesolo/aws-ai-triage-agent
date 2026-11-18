import json
import sys
import unittest
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "lambda"))

from triage import build_message, lookup_attribute, parse_finding  # noqa: E402

EVENTS = ROOT / "tests" / "events"


def load(name):
    return json.loads((EVENTS / name).read_text())


class ParseFinding(unittest.TestCase):
    def test_finding_without_resource(self):
        finding = parse_finding(load("sample-finding.json"))
        self.assertEqual(finding["severity"], 2)
        self.assertIsNone(finding["user_name"])

    def test_finding_with_user(self):
        finding = parse_finding(load("finding-with-user.json"))
        self.assertEqual(finding["user_name"], "nate-admin")

    def test_missing_required_field_fails_loudly(self):
        event = load("sample-finding.json")
        del event["detail"]["type"]
        with self.assertRaises(KeyError):
            parse_finding(event)


class LookupAttribute(unittest.TestCase):
    def test_no_identity_means_no_lookup(self):
        self.assertIsNone(lookup_attribute(parse_finding(load("sample-finding.json"))))

    def test_placeholder_key_falls_back_to_user(self):
        lookup = lookup_attribute(parse_finding(load("finding-with-user.json")))
        self.assertEqual(lookup, {"AttributeKey": "Username", "AttributeValue": "nate-admin"})


class BuildMessage(unittest.TestCase):
    def setUp(self):
        self.finding = parse_finding(load("finding-with-user.json"))
        self.lookup = lookup_attribute(self.finding)

    def test_lists_events(self):
        events = [{
            "EventTime": datetime(2026, 11, 18, 16, 0, tzinfo=timezone.utc),
            "EventName": "ConsoleLogin",
            "EventSource": "signin.amazonaws.com",
        }]
        message = build_message(self.finding, events, self.lookup)
        self.assertIn("Recent activity for nate-admin", message)
        self.assertIn("ConsoleLogin", message)

    def test_caps_events_at_five(self):
        event = {
            "EventTime": datetime(2026, 11, 18, tzinfo=timezone.utc),
            "EventName": "GetObject",
            "EventSource": "s3.amazonaws.com",
        }
        message = build_message(self.finding, [event] * 10, self.lookup)
        self.assertEqual(message.count("GetObject"), 5)

    def test_lookup_failure_still_alerts(self):
        message = build_message(self.finding, None, self.lookup)
        self.assertIn("lookup failed", message)
        self.assertIn("GuardDuty finding", message)


if __name__ == "__main__":
    unittest.main()
