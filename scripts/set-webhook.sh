#!/usr/bin/env bash
# Stores the Slack webhook from the clipboard in SSM Parameter Store.
# Usage: copy the webhook URL in Slack, then run ./scripts/set-webhook.sh
set -euo pipefail

url="$(pbpaste)"

if [[ "$url" != https://hooks.slack.com/services/* ]]; then
  echo "Clipboard doesn't hold a Slack webhook URL. Copy it in Slack and run this again." >&2
  exit 1
fi

aws ssm put-parameter \
  --name /triage-agent/slack-webhook \
  --type SecureString \
  --value "$url" \
  --overwrite \
  --profile solo >/dev/null

echo "Saved webhook (${#url} characters) to /triage-agent/slack-webhook"
