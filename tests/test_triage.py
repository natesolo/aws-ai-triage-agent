import json
import sys
import unittest
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "lambda"))

from triage import build_message, is_write, lookup_attribute, parse_finding, prioritize  # noqa: E402

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


def ct_event(name, read_only, minute=0):
    return {
        "EventTime": datetime(2026, 11, 19, 15, minute, tzinfo=timezone.utc),
        "EventName": name,
        "EventSource": "iam.amazonaws.com",
        "CloudTrailEvent": json.dumps({"readOnly": read_only}),
    }


class WriteFirst(unittest.TestCase):
    def test_detects_write(self):
        self.assertTrue(is_write(ct_event("CreateUser", False)))
        self.assertFalse(is_write(ct_event("GetUser", True)))

    def test_missing_or_bad_detail_counts_as_read(self):
        self.assertFalse(is_write({"EventName": "X"}))
        self.assertFalse(is_write({"EventName": "X", "CloudTrailEvent": "not json"}))

    def test_writes_come_first_and_keep_order(self):
        events = [
            ct_event("GetUser", True, 5),
            ct_event("CreateUser", False, 4),
            ct_event("ListRoles", True, 3),
            ct_event("AttachRolePolicy", False, 2),
        ]
        names = [e["EventName"] for e in prioritize(events)]
        self.assertEqual(names, ["CreateUser", "AttachRolePolicy", "GetUser", "ListRoles"])

    def test_write_survives_the_five_event_cap(self):
        finding = parse_finding(load("finding-with-user.json"))
        lookup = lookup_attribute(finding)
        events = [ct_event("GetUser", True)] * 10 + [ct_event("PutBucketPolicy", False)]
        message = build_message(finding, events, lookup)
        self.assertIn("WRITE", message)
        self.assertIn("PutBucketPolicy", message)
        self.assertIn("1 write / 10 read", message)


if __name__ == "__main__":
    unittest.main()
