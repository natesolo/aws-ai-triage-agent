locals {
  bedrock_model       = "anthropic.claude-haiku-4-5-20251001-v1:0"
  bedrock_profile     = "us.${local.bedrock_model}"
  bedrock_profile_arn = "arn:aws:bedrock:${data.aws_region.current.region}:${local.account_id}:inference-profile/${local.bedrock_profile}"

  # Regions the "us." inference profile can route to from us-east-1.
  bedrock_regions = ["us-east-1", "us-east-2", "us-west-2"]
}

resource "aws_iam_role_policy" "invoke_bedrock" {
  name = "invoke-claude-haiku"
  role = aws_iam_role.lambda.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid      = "InferenceProfile"
        Effect   = "Allow"
        Action   = "bedrock:InvokeModel"
        Resource = local.bedrock_profile_arn
      },
      {
        Sid      = "ModelOnlyThroughProfile"
        Effect   = "Allow"
        Action   = "bedrock:InvokeModel"
        Resource = [for r in local.bedrock_regions : "arn:aws:bedrock:${r}::foundation-model/${local.bedrock_model}"]
        Condition = {
          StringEquals = { "bedrock:InferenceProfileArn" = local.bedrock_profile_arn }
        }
      }
    ]
  })
}
