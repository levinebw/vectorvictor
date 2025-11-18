# Vulnerable AWS IAM Configuration
# OWASP Cloud Security - Insecure Identity and Access Management

# VULNERABLE: IAM user with access keys (long-term credentials)
resource "aws_iam_user" "vulnerable_user" {
  name = "vulnerable-service-account"
  path = "/system/"

  # VULNERABLE: No force_destroy protection
  force_destroy = true

  tags = {
    Name = "Vulnerable User"
  }
}

# VULNERABLE: Access key for IAM user (should use roles)
resource "aws_iam_access_key" "vulnerable_access_key" {
  user = aws_iam_user.vulnerable_user.name

  # VULNERABLE: Access keys should be rotated and not managed in Terraform
}

# VULNERABLE: Overly permissive IAM policy - Admin access
resource "aws_iam_user_policy" "admin_policy" {
  name = "admin-access"
  user = aws_iam_user.vulnerable_user.name

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = "*"  # VULNERABLE: All actions
        Resource = "*"  # VULNERABLE: All resources
      }
    ]
  })
}

# VULNERABLE: IAM role with overly broad permissions
resource "aws_iam_role" "vulnerable_lambda_role" {
  name = "vulnerable-lambda-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = {
          Service = "lambda.amazonaws.com"
        }
        Action = "sts:AssumeRole"
      },
      {
        # VULNERABLE: Any AWS account can assume this role
        Effect = "Allow"
        Principal = {
          AWS = "*"  # VULNERABLE: Wildcard principal
        }
        Action = "sts:AssumeRole"
      }
    ]
  })
}

# VULNERABLE: Policy allowing privilege escalation
resource "aws_iam_role_policy" "privilege_escalation" {
  name = "dangerous-permissions"
  role = aws_iam_role.vulnerable_lambda_role.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "iam:CreateAccessKey",  # VULNERABLE: Can create access keys
          "iam:CreateUser",       # VULNERABLE: Can create users
          "iam:AttachUserPolicy", # VULNERABLE: Can attach policies
          "iam:PutUserPolicy",    # VULNERABLE: Can add inline policies
          "iam:UpdateAssumeRolePolicy",  # VULNERABLE: Can modify trust policy
          "iam:PassRole"          # VULNERABLE: Can pass roles
        ]
        Resource = "*"
      }
    ]
  })
}

# VULNERABLE: IAM group with password policy disabled
resource "aws_iam_group" "vulnerable_group" {
  name = "developers"
  path = "/users/"
}

# VULNERABLE: No password policy defined (should be strict)
resource "aws_iam_account_password_policy" "weak_password_policy" {
  minimum_password_length        = 6  # VULNERABLE: Too short
  require_lowercase_characters   = false  # VULNERABLE: Should be true
  require_numbers                = false  # VULNERABLE: Should be true
  require_uppercase_characters   = false  # VULNERABLE: Should be true
  require_symbols                = false  # VULNERABLE: Should be true
  allow_users_to_change_password = true
  max_password_age               = 0  # VULNERABLE: No expiration
  password_reuse_prevention      = 0  # VULNERABLE: Can reuse passwords
}

# VULNERABLE: Policy with NotAction (inverse logic - dangerous)
resource "aws_iam_policy" "dangerous_not_action" {
  name        = "dangerous-policy"
  path        = "/"
  description = "Policy using NotAction"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect    = "Allow"
        NotAction = "iam:DeleteUser"  # VULNERABLE: Allows everything except this
        Resource  = "*"
      }
    ]
  })
}

# VULNERABLE: Role allowing cross-account access without conditions
resource "aws_iam_role" "cross_account_vulnerable" {
  name = "cross-account-access"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = {
          AWS = "arn:aws:iam::123456789012:root"  # VULNERABLE: Entire account can assume
        }
        Action = "sts:AssumeRole"
        # VULNERABLE: No ExternalId condition
        # VULNERABLE: No MFA condition
      }
    ]
  })
}

# VULNERABLE: Service role with S3 full access
resource "aws_iam_role_policy_attachment" "s3_full_access" {
  role       = aws_iam_role.vulnerable_lambda_role.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonS3FullAccess"  # VULNERABLE: Too broad
}

# VULNERABLE: Inline policy with data exfiltration risk
resource "aws_iam_user_policy" "data_exfiltration_risk" {
  name = "s3-access"
  user = aws_iam_user.vulnerable_user.name

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "s3:GetObject",
          "s3:ListBucket",
          "s3:PutObject",  # VULNERABLE: Can upload to any bucket
          "s3:PutBucketPolicy"  # VULNERABLE: Can modify bucket policies
        ]
        Resource = "*"
      }
    ]
  })
}

# VULNERABLE: Role for EC2 with secrets access
resource "aws_iam_role" "ec2_with_secrets" {
  name = "ec2-secrets-access"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "ec2.amazonaws.com"
        }
      }
    ]
  })
}

# VULNERABLE: Secrets Manager full access
resource "aws_iam_role_policy" "secrets_full_access" {
  name = "secrets-access"
  role = aws_iam_role.ec2_with_secrets.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "secretsmanager:*"  # VULNERABLE: All secrets manager actions
        ]
        Resource = "*"
      }
    ]
  })
}

# VULNERABLE: Policy allowing sts:AssumeRole on any role
resource "aws_iam_policy" "assume_any_role" {
  name        = "assume-any-role"
  description = "Can assume any role"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = "sts:AssumeRole"
        Resource = "*"  # VULNERABLE: Can assume any role
      }
    ]
  })
}

# VULNERABLE: Root account access keys (should never exist)
# Note: This is conceptual - you can't actually create root access keys via Terraform
# But detecting such keys in state or config is critical

# VULNERABLE: No MFA requirement for sensitive operations
# Missing: MFA conditions in policies for sensitive actions
