resource "aws_cloudwatch_event_rule" "guardduty_findings" {
  name        = "triage-agent-guardduty-findings"
  description = "Route GuardDuty findings to the triage agent"

  event_pattern = jsonencode({
    source        = ["aws.guardduty"]
    "detail-type" = ["GuardDuty Finding"]
  })
}