import json
import os
import urllib.request
from datetime import datetime, timedelta, timezone

import boto3
from botocore.config import Config

from ai import AI_UNAVAILABLE, build_request, format_triage, parse_response
from triage import LOOKUP_LIMIT, build_message, lookup_attribute, parse_finding

ssm = boto3.client("ssm")
cloudtrail = boto3.client("cloudtrail")
# First call with a new schema can take ~90s while Bedrock compiles it.
bedrock = boto3.client("bedrock-runtime", config=Config(read_timeout=100, retries={"max_attempts": 2}))
_webhook = None


def get_webhook():
    global _webhook
    if _webhook is None:
        resp = ssm.get_parameter(Name=os.environ["WEBHOOK_PARAM"], WithDecryption=True)
        _webhook = resp["Parameter"]["Value"]
    return _webhook


def recent_events(lookup):
    if lookup is None:
        return []
    end = datetime.now(timezone.utc)
    resp = cloudtrail.lookup_events(
        LookupAttributes=[lookup],
        StartTime=end - timedelta(hours=24),
        EndTime=end,
        MaxResults=LOOKUP_LIMIT,
    )
    return resp.get("Events", [])


def ai_section(finding, events):
    try:
        response = bedrock.converse(**build_request(os.environ["BEDROCK_MODEL_ID"], finding, events))
        return format_triage(parse_response(response))
    except Exception as exc:  # AI is a bonus; the alert must still go out
        print(f"AI triage failed: {exc}")
        return AI_UNAVAILABLE


def post_to_slack(text):
    req = urllib.request.Request(
        get_webhook(),
        data=json.dumps({"text": text}).encode(),
        headers={"Content-Type": "application/json"},
    )
    with urllib.request.urlopen(req, timeout=5) as resp:
        print(f"Slack responded {resp.status}")


def handler(event, context):
    finding = parse_finding(event)
    lookup = lookup_attribute(finding)

    try:
        events = recent_events(lookup)
    except Exception as exc:  # enrichment must never block the alert
        print(f"CloudTrail lookup failed: {exc}")
        events = None

    message = build_message(finding, events, lookup)
    post_to_slack(f"{message}\n\n{ai_section(finding, events)}")
    return {"ok": True}
