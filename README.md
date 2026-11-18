# AWS AI Triage Agent

A Terraform-deployed AWS pipeline that sends GuardDuty findings to Slack, enriches them with CloudTrail context, and adds AI-assisted triage.

## How it works
GuardDuty findings go to EventBridge, which invokes a Python Lambda. Lambda looks up the last 24 hours of CloudTrail activity for the user or access key in the finding, then posts an alert to Slack. The webhook is stored as an encrypted SSM parameter.

## Security
- CloudTrail logs to a private, encrypted S3 bucket that only allows HTTPS access.
- IAM Access Analyzer reports external access, and expected SSO roles are archived through a narrow Terraform rule.
- The Lambda role can read only its webhook parameter and write only to its own log group.
