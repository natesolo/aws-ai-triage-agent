# AWS AI Triage Agent

[![CI/CD](https://github.com/natesolo/aws-ai-triage-agent/actions/workflows/deploy.yml/badge.svg)](https://github.com/natesolo/aws-ai-triage-agent/actions/workflows/deploy.yml)

Sends AWS GuardDuty findings to Slack with CloudTrail context and an AI triage summary. Deployed with Terraform through GitHub Actions.

![Prompt injection attempt, triaged as HIGH anyway](docs/injection-test.png)

## Architecture

```mermaid
flowchart LR
    GD[GuardDuty] --> EB[EventBridge]
    EB --> L[Lambda]
    L --> CT[CloudTrail<br/>last 24h]
    L --> BR[Bedrock<br/>Claude Haiku 4.5]
    L --> SSM[SSM<br/>webhook]
    L --> S[Slack #alerts]
```

1. GuardDuty raises a finding. EventBridge invokes the Lambda.
2. Lambda pulls the last 24h of CloudTrail activity for the user or access key. Write actions are listed first.
3. Bedrock returns a severity, summary, likely-benign flag, and up to 3 next steps.
4. Lambda posts the alert to Slack. If CloudTrail or Bedrock fails, the alert still goes out.

## AI safety

- **Read-only.** The agent suggests next steps. A human decides. No automatic remediation.
- **Logs are untrusted.** Finding and CloudTrail data go inside `<finding>` and `<cloudtrail>` tags. The prompt says never to follow instructions in them, and `<` is escaped so data can't close the tags.
- **Structured output.** Bedrock must return JSON that matches a schema. The Lambda validates it again: allowed severities only, correct types, length caps.
- **Slack escaping.** All finding data and model output are escaped, so log text can't ping `@channel` or post fake links.
- **Tested.** `tests/events/injection-attempt.json` tells the model to downgrade the finding and post `@channel`. It still triages it as HIGH.

## Security

- **Least privilege.** Lambda can read one SSM parameter, write to its own log group, and invoke one Bedrock model, only through its inference profile.
- **CloudTrail** logs to a private, encrypted S3 bucket that only allows HTTPS.
- **IAM Access Analyzer** reports external access. Expected SSO roles are archived through a narrow rule.
- **No long-lived keys.** GitHub Actions uses OIDC. The trust policy matches the repo's owner and repo IDs, so a re-created repo with the same name can't assume the roles.

## CI/CD

| Event | AWS role | Steps |
|---|---|---|
| Pull request | `github-actions-plan` (read-only) | unit tests, `fmt`, `validate`, `plan` |
| Push to `main` | `github-actions-deploy` | same, then `apply` the saved plan |

Terraform state is in a versioned, private S3 bucket with native locking (`use_lockfile`).

## Tests

```bash
python3 -m unittest discover tests
```

24 unit tests cover finding parsing, CloudTrail ordering, Bedrock request building, response validation, and Slack escaping. No AWS credentials needed.

## Deploy

Requires Terraform 1.10+, AWS CLI v2 with SSO, and a Slack incoming webhook.

```bash
export AWS_PROFILE=solo
terraform init
terraform apply
./scripts/set-webhook.sh   # copy the webhook URL first
```

## Limitations

- Tested with GuardDuty sample findings, not real attacks.
- The deploy role has `AdministratorAccess`, limited by the trust policy. Next step: a permissions boundary and a required approval before `apply`.
- No de-duplication of repeated findings yet.
