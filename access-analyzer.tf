resource "aws_accessanalyzer_analyzer" "account" {
  analyzer_name = "triage-agent-external-access"
  type          = "ACCOUNT"
}

# Identity Center roles trust this account's own SSO SAML provider.
# Expected access, so archive those findings automatically.
resource "aws_accessanalyzer_archive_rule" "identity_center" {
  analyzer_name = aws_accessanalyzer_analyzer.account.analyzer_name
  rule_name     = "identity-center-sso-roles"

  filter {
    criteria = "resourceType"
    eq       = ["AWS::IAM::Role"]
  }

  filter {
    criteria = "principal.Federated"
    contains = ["saml-provider/AWSSSO_"]
  }
}
