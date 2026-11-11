import json
import os
import urllib.request

import boto3

ssm = boto3.client("ssm")
_webhook = None


def get_webhook():
    global _webhook
    if _webhook is None:
        resp = ssm.get_parameter(Name=os.environ["WEBHOOK_PARAM"], WithDecryption=True)
        _webhook = resp["Parameter"]["Value"]
    return _webhook


def handler(event, context):
    detail = event["detail"]
    text = (
        "*GuardDuty finding*\n"
        f"Type: {detail['type']}\n"
        f"Severity: {detail['severity']}\n"
        f"Title: {detail['title']}\n"
        f"Region: {detail['region']}\n"
        f"Account: {detail['accountId']}"
    )
    req = urllib.request.Request(
        get_webhook(),
        data=json.dumps({"text": text}).encode(),
        headers={"Content-Type": "application/json"},
    )
    with urllib.request.urlopen(req, timeout=5) as resp:
        print(f"Slack responded {resp.status}")
    return {"ok": True}