"""Parsing and formatting for GuardDuty findings.

No AWS calls here, so this file can be unit tested without credentials.
"""

import json

MAX_EVENTS = 5
LOOKUP_LIMIT = 50
PLACEHOLDER_PREFIX = "GeneratedFinding"


def parse_finding(event):
    detail = event["detail"]
    key = detail.get("resource", {}).get("accessKeyDetails", {})
    return {
        "type": detail["type"],
        "severity": detail["severity"],
        "title": detail["title"],
        "region": detail["region"],
        "account_id": detail["accountId"],
        "user_name": key.get("userName"),
        "access_key_id": key.get("accessKeyId"),
    }


def _real(value):
    return bool(value) and not value.startswith(PLACEHOLDER_PREFIX)


def lookup_attribute(finding):
    """Pick the CloudTrail lookup that best matches the finding, or None."""
    if _real(finding["access_key_id"]):
        return {"AttributeKey": "AccessKeyId", "AttributeValue": finding["access_key_id"]}
    if _real(finding["user_name"]):
        return {"AttributeKey": "Username", "AttributeValue": finding["user_name"]}
    return None


def is_write(event):
    """True when CloudTrail marks the call as changing something."""
    try:
        detail = json.loads(event.get("CloudTrailEvent") or "{}")
    except ValueError:
        return False
    return detail.get("readOnly") is False


def prioritize(events):
    """Writes first, then reads. Each group keeps CloudTrail's newest-first order."""
    writes = [e for e in events if is_write(e)]
    reads = [e for e in events if not is_write(e)]
    return writes + reads


def _event_line(event):
    time = event["EventTime"].strftime("%Y-%m-%d %H:%M UTC")
    tag = "WRITE " if is_write(event) else ""
    return f"• {tag}{time}  {event['EventName']}  ({event.get('EventSource', 'unknown')})"


def build_message(finding, events, lookup):
    lines = [
        "*GuardDuty finding*",
        f"Type: {finding['type']}",
        f"Severity: {finding['severity']}",
        f"Title: {finding['title']}",
        f"Region: {finding['region']}",
        f"Account: {finding['account_id']}",
        "",
    ]

    if lookup is None:
        lines.append("_CloudTrail context: no real user or access key in this finding._")
    elif events is None:
        lines.append("_CloudTrail context: lookup failed, check the Lambda logs._")
    elif not events:
        lines.append(f"_CloudTrail context: no activity for {lookup['AttributeValue']} in the last 24h._")
    else:
        ordered = prioritize(events)
        writes = sum(1 for e in ordered if is_write(e))
        lines.append(
            f"*Recent activity for {lookup['AttributeValue']} (last 24h, "
            f"{writes} write / {len(ordered) - writes} read, writes first):*"
        )
        lines.extend(_event_line(e) for e in ordered[:MAX_EVENTS])

    return "\n".join(lines)
