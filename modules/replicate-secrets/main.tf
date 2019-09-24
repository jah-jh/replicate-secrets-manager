data "aws_caller_identity" "current" {}

#Create trail
resource "aws_cloudtrail" "replicate_secrets" {
  name                       = "replicate_secrets"
  s3_bucket_name             = "${aws_s3_bucket.repl_log_bucket.id}"
  s3_key_prefix              = "prefix"
  cloud_watch_logs_role_arn  = "${aws_iam_role.cloudtrail_cloudwatch_events_role.arn}"
  cloud_watch_logs_group_arn = "${aws_cloudwatch_log_group.default.arn}"
  depends_on                 = ["aws_s3_bucket.repl_log_bucket", "aws_iam_role_policy.policy", "aws_s3_bucket_policy.AllowCloudTrail"]

  include_global_service_events = false

  event_selector {
    read_write_type = "WriteOnly"
  }
}

#create se_bucket
resource "aws_s3_bucket" "repl_log_bucket" {
  bucket_prefix = "replicate-secrets-"
  force_destroy = true
}

resource "aws_s3_bucket_policy" "AllowCloudTrail" {
  bucket = "${aws_s3_bucket.repl_log_bucket.id}"

  policy = <<POLICY
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Sid": "AWSCloudTrailAclCheck",
            "Effect": "Allow",
            "Principal": {
              "Service": "cloudtrail.amazonaws.com"
            },
            "Action": "s3:GetBucketAcl",
            "Resource": "${aws_s3_bucket.repl_log_bucket.arn}"
        },
        {
            "Sid": "AWSCloudTrailWrite",
            "Effect": "Allow",
            "Principal": {
              "Service": "cloudtrail.amazonaws.com"
            },
            "Action": "s3:PutObject",
            "Resource": "arn:aws:s3:::${aws_s3_bucket.repl_log_bucket.id}/prefix/AWSLogs/${data.aws_caller_identity.current.account_id}/*",
            "Condition": {
                "StringEquals": {
                    "s3:x-amz-acl": "bucket-owner-full-control"
                }
            }
        }
    ]
}
POLICY
}

#Role cloudtrail
resource "aws_iam_role" "cloudtrail_cloudwatch_events_role" {
  name_prefix        = "cloudtrail_events_role"
  assume_role_policy = "${data.aws_iam_policy_document.assume_policy.json}"
}

#ClousdTrail role policy
resource "aws_iam_role_policy" "policy" {
  name_prefix = "cloudtrail_cloudwatch_events_policy"
  role        = "${aws_iam_role.cloudtrail_cloudwatch_events_role.id}"
  policy      = "${data.aws_iam_policy_document.policy.json}"
}

#Policy add perm  to trail to create and write in cloudwatch logstream
data "aws_iam_policy_document" "policy" {
  statement {
    effect  = "Allow"
    actions = ["logs:CreateLogStream"]

    resources = [
      "arn:aws:logs:${var.source-region}:${data.aws_caller_identity.current.account_id}:log-group:${aws_cloudwatch_log_group.default.name}:log-stream:*",
    ]
  }

  statement {
    effect  = "Allow"
    actions = ["logs:PutLogEvents"]

    resources = [
      "arn:aws:logs:${var.source-region}:${data.aws_caller_identity.current.account_id}:log-group:${aws_cloudwatch_log_group.default.name}:log-stream:*",
    ]
  }
}

#Assume cloudtrail
data "aws_iam_policy_document" "assume_policy" {
  statement {
    effect  = "Allow"
    actions = ["sts:AssumeRole"]

    principals = {
      type        = "Service"
      identifiers = ["cloudtrail.amazonaws.com"]
    }
  }
}

#Create cloudwatch group
resource "aws_cloudwatch_log_group" "default" {
  name_prefix = "cloudtrail_repsec"
}

#Role for repl secret
resource "aws_iam_role" "replicate_secret" {
  name_prefix        = "replicate_secret"
  assume_role_policy = "${data.aws_iam_policy_document.AssumeRoleReplicate.json}"
}

resource "aws_iam_role_policy" "replicateSecretsRole" {
  name_prefix = "replicateSecrets"
  role        = "${aws_iam_role.replicate_secret.id}"
  policy      = "${data.aws_iam_policy_document.PermToReplicate.json}"
}

data "aws_iam_policy_document" "PermToReplicate" {
  statement {
    effect = "Allow"

    actions = [
      "secretsmanager:GetSecretValue",
      "secretsmanager:DescribeSecret",
      "secretsmanager:PutSecretValue",
      "secretsmanager:CreateSecret",
      "secretsmanager:ListSecrets",
    ]

    resources = ["arn:aws:secretsmanager:*:*:secret:*"]
    effect    = "Allow"
  }

  #Perm for lambda logging
  statement {
    effect = "Allow"

    actions = [
      "logs:CreateLogGroup",
      "logs:PutLogEvents",
      "logs:CreateLogStream",
    ]

    resources = [
      "arn:aws:logs:${var.source-region}:${data.aws_caller_identity.current.account_id}:*",
    ]
  }

  statement {
    effect = "Allow"

    actions = [
      "kms:ListKeys",
      "kms:TagResource",
      "kms:ListKeyPolicies",
      "kms:ListAliases",
      "kms:GetKeyPolicy",
      "kms:CreateAlias",
      "kms:DescribeKey",
      "kms:CreateKey",
      "kms:ListResourceTags",
      "kms:Decrypt",
      "kms:Encrypt",
      "kms:GenerateDataKey",
    ]

    resources = [
      "*",
    ]
  }
}

data "aws_iam_policy_document" "AssumeRoleReplicate" {
  statement {
    effect  = "Allow"
    actions = ["sts:AssumeRole"]

    principals = {
      type        = "Service"
      identifiers = ["lambda.amazonaws.com"]
    }
  }
}

data "archive_file" "lambda_function" {
  type        = "zip"
  source_file = "./lambda_function.py"
  output_path = "./lambda_function.zip"
}

#Create Lambda function and assign role
resource "aws_lambda_function" "ReplicatorLambda" {
  timeout          = 15
  filename         = "lambda_function.zip"
  function_name    = "ReplicateSecretsToTargetRegion"
  description      = "Lambda to replicate secrets"
  source_code_hash = "${data.archive_file.lambda_function.output_base64sha256}"
  role             = "${aws_iam_role.replicate_secret.arn}"
  runtime          = "python3.7"
  handler          = "lambda_function.lambda_handler"

  environment {
    variables = {
      TargetRegion = "${var.target-region}"
    }
  }
}

#CloudWatch Event pattern and rule for PutSecretValue 
resource "aws_cloudwatch_event_rule" "InvokeLambdaPutSecret" {
  name        = "InvOnPutSecret"
  description = "Invoke lambda on PutSecretValue"
  is_enabled  = true

  event_pattern = <<PATTERN
{
  "source": [
    "aws.secretsmanager"
  ],
  "detail-type": [
    "AWS API Call via CloudTrail"
  ],
  "detail": {
    "eventSource": [
      "secretsmanager.amazonaws.com"
    ],
    "eventName": [
      "PutSecretValue"
    ]
  }
}
PATTERN
}

#CloudWatch Event pattern and rule for CreateSecret
resource "aws_cloudwatch_event_rule" "InvokeLambdaCreateSecret" {
  name        = "InvOnCreareSecret"
  description = "Invoke lambda on CreateSecret"
  is_enabled  = true

  event_pattern = <<PATTERN
{
  "source": [
    "aws.secretsmanager"
  ],
  "detail-type": [
    "AWS API Call via CloudTrail"
  ],
  "detail": {
    "eventSource": [
      "secretsmanager.amazonaws.com"
    ],
    "eventName": [
      "CreateSecret"
    ]
  }
}
PATTERN
}

#Create lambda invokation PutSecretValue
resource "aws_cloudwatch_event_target" "lambdaPutSecret" {
  rule = "${aws_cloudwatch_event_rule.InvokeLambdaPutSecret.name}"
  arn  = "${aws_lambda_function.ReplicatorLambda.arn}"
}

#Lambda invokation CreateSecret
resource "aws_cloudwatch_event_target" "lambdaCreateSecret" {
  rule = "${aws_cloudwatch_event_rule.InvokeLambdaCreateSecret.name}"
  arn  = "${aws_lambda_function.ReplicatorLambda.arn}"
}

#Permissions for lambda invocation PutSecretValue
resource "aws_lambda_permission" "PermissionForInvocationPutSecret" {
  statement_id  = "AllowExecutionOnPutSecret"
  action        = "lambda:InvokeFunction"
  function_name = "${aws_lambda_function.ReplicatorLambda.function_name}"
  principal     = "events.amazonaws.com"
  source_arn    = "${aws_cloudwatch_event_rule.InvokeLambdaPutSecret.arn}"
}

#Permissions for lambda invocation CreateSecret
resource "aws_lambda_permission" "PermissionForInvocationCreateSecret" {
  statement_id  = "AllowExecutionOnCreateSecret"
  action        = "lambda:InvokeFunction"
  function_name = "${aws_lambda_function.ReplicatorLambda.function_name}"
  principal     = "events.amazonaws.com"
  source_arn    = "${aws_cloudwatch_event_rule.InvokeLambdaCreateSecret.arn}"
}
