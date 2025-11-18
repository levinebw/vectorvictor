# Vulnerable Miscellaneous AWS Resources
# Various security misconfigurations across AWS services

# VULNERABLE: CloudFront distribution without security headers
resource "aws_cloudfront_distribution" "vulnerable_cdn" {
  enabled             = true
  is_ipv6_enabled     = true
  comment             = "Vulnerable CloudFront distribution"
  default_root_object = "index.html"

  origin {
    domain_name = "vulnerable-bucket.s3.amazonaws.com"
    origin_id   = "S3-vulnerable-bucket"

    # VULNERABLE: Using HTTP instead of HTTPS
    custom_origin_config {
      http_port              = 80
      https_port             = 443
      origin_protocol_policy = "http-only"  # VULNERABLE: Not enforcing HTTPS
      origin_ssl_protocols   = ["TLSv1", "TLSv1.1"]  # VULNERABLE: Outdated TLS
    }
  }

  default_cache_behavior {
    allowed_methods  = ["GET", "HEAD", "OPTIONS", "PUT", "POST", "PATCH", "DELETE"]
    cached_methods   = ["GET", "HEAD"]
    target_origin_id = "S3-vulnerable-bucket"

    forwarded_values {
      query_string = true
      cookies {
        forward = "all"  # VULNERABLE: Forwarding all cookies
      }
    }

    viewer_protocol_policy = "allow-all"  # VULNERABLE: Not enforcing HTTPS
    min_ttl                = 0
    default_ttl            = 3600
    max_ttl                = 86400
  }

  # VULNERABLE: No geo restrictions
  restrictions {
    geo_restriction {
      restriction_type = "none"
    }
  }

  viewer_certificate {
    cloudfront_default_certificate = true  # VULNERABLE: Using default cert
    minimum_protocol_version       = "TLSv1"  # VULNERABLE: Old TLS version
  }

  # VULNERABLE: No WAF associated
  # Missing: web_acl_id

  # VULNERABLE: Logging disabled
  # Missing: logging_config
}

# VULNERABLE: Lambda function with excessive permissions
resource "aws_lambda_function" "vulnerable_lambda" {
  filename         = "lambda.zip"
  function_name    = "vulnerable_function"
  role             = aws_iam_role.vulnerable_lambda_role.arn
  handler          = "index.handler"
  source_code_hash = filebase64sha256("lambda.zip")
  runtime          = "python3.7"  # VULNERABLE: Outdated runtime

  # VULNERABLE: Environment variables with secrets
  environment {
    variables = {
      DB_PASSWORD      = "SuperSecret123!"  # VULNERABLE: Hardcoded secret
      API_KEY          = "sk-1234567890"    # VULNERABLE: Hardcoded API key
      AWS_ACCESS_KEY   = "AKIAIOSFODNN7"   # VULNERABLE: Hardcoded credentials
    }
  }

  # VULNERABLE: No VPC configuration (unrestricted network access)
  # Missing: vpc_config

  # VULNERABLE: No dead letter queue
  # Missing: dead_letter_config

  # VULNERABLE: Tracing disabled
  tracing_config {
    mode = "PassThrough"  # Should be "Active"
  }

  # VULNERABLE: Reserved concurrent executions not set
  # Can lead to unbounded consumption
}

# VULNERABLE: API Gateway without authentication
resource "aws_api_gateway_rest_api" "vulnerable_api" {
  name        = "vulnerable-api"
  description = "API without proper security"

  # VULNERABLE: No API key required
  # VULNERABLE: No throttling configured
}

resource "aws_api_gateway_resource" "vulnerable_resource" {
  rest_api_id = aws_api_gateway_rest_api.vulnerable_api.id
  parent_id   = aws_api_gateway_rest_api.vulnerable_api.root_resource_id
  path_part   = "data"
}

resource "aws_api_gateway_method" "vulnerable_method" {
  rest_api_id   = aws_api_gateway_rest_api.vulnerable_api.id
  resource_id   = aws_api_gateway_resource.vulnerable_resource.id
  http_method   = "GET"
  authorization = "NONE"  # VULNERABLE: No authorization

  # VULNERABLE: No API key required
  api_key_required = false
}

# VULNERABLE: SNS topic with open access
resource "aws_sns_topic" "vulnerable_topic" {
  name = "vulnerable-notifications"

  # VULNERABLE: No encryption at rest
  # Missing: kms_master_key_id
}

resource "aws_sns_topic_policy" "vulnerable_sns_policy" {
  arn = aws_sns_topic.vulnerable_topic.arn

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = "*"  # VULNERABLE: Public access
        Action = [
          "SNS:Subscribe",
          "SNS:Receive",
          "SNS:Publish"  # VULNERABLE: Anyone can publish
        ]
        Resource = aws_sns_topic.vulnerable_topic.arn
      }
    ]
  })
}

# VULNERABLE: SQS queue with public access
resource "aws_sqs_queue" "vulnerable_queue" {
  name                      = "vulnerable-queue"
  delay_seconds             = 0
  max_message_size          = 262144
  message_retention_seconds = 345600

  # VULNERABLE: No encryption
  # Missing: kms_master_key_id

  # VULNERABLE: No dead letter queue
  # Missing: redrive_policy
}

resource "aws_sqs_queue_policy" "vulnerable_queue_policy" {
  queue_url = aws_sqs_queue.vulnerable_queue.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = "*"  # VULNERABLE: Public access
        Action = "sqs:*"  # VULNERABLE: All actions
        Resource = aws_sqs_queue.vulnerable_queue.arn
      }
    ]
  })
}

# VULNERABLE: Secrets Manager secret without rotation
resource "aws_secretsmanager_secret" "vulnerable_secret" {
  name        = "vulnerable/db/password"
  description = "Database password without rotation"

  # VULNERABLE: No automatic rotation
  # Missing: rotation_lambda_arn
  # Missing: rotation_rules

  # VULNERABLE: Recovery window too short
  recovery_window_in_days = 0  # Immediate deletion
}

resource "aws_secretsmanager_secret_version" "vulnerable_secret_value" {
  secret_id = aws_secretsmanager_secret.vulnerable_secret.id

  # VULNERABLE: Plaintext secret in Terraform
  secret_string = jsonencode({
    username = "admin"
    password = "HardcodedPassword123!"
  })
}

# VULNERABLE: KMS key with overly permissive policy
resource "aws_kms_key" "vulnerable_key" {
  description             = "Vulnerable KMS key"
  deletion_window_in_days = 7  # VULNERABLE: Short deletion window

  # VULNERABLE: Key rotation disabled
  enable_key_rotation = false

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "Enable IAM User Permissions"
        Effect = "Allow"
        Principal = {
          AWS = "*"  # VULNERABLE: Wildcard principal
        }
        Action   = "kms:*"  # VULNERABLE: All KMS actions
        Resource = "*"
      }
    ]
  })
}

# VULNERABLE: CloudWatch log group without encryption
resource "aws_cloudwatch_log_group" "vulnerable_logs" {
  name = "/aws/vulnerable/logs"

  # VULNERABLE: No encryption
  # Missing: kms_key_id

  # VULNERABLE: Short retention
  retention_in_days = 1

  tags = {
    Environment = "vulnerable"
  }
}

# VULNERABLE: Elasticsearch domain without encryption
resource "aws_elasticsearch_domain" "vulnerable_es" {
  domain_name           = "vulnerable-es"
  elasticsearch_version = "6.0"  # VULNERABLE: Outdated version

  cluster_config {
    instance_type = "t2.small.elasticsearch"
  }

  # VULNERABLE: No encryption at rest
  encrypt_at_rest {
    enabled = false
  }

  # VULNERABLE: No node-to-node encryption
  node_to_node_encryption {
    enabled = false
  }

  # VULNERABLE: No enforce HTTPS
  domain_endpoint_options {
    enforce_https       = false
    tls_security_policy = "Policy-Min-TLS-1-0-2019-07"  # VULNERABLE: Old TLS
  }

  # VULNERABLE: Publicly accessible
  # Missing: vpc_options

  # VULNERABLE: No cognito authentication
  # Missing: cognito_options
}

# VULNERABLE: EKS cluster without logging
resource "aws_eks_cluster" "vulnerable_eks" {
  name     = "vulnerable-cluster"
  role_arn = "arn:aws:iam::123456789012:role/eks-cluster-role"

  vpc_config {
    subnet_ids = ["subnet-12345", "subnet-67890"]

    # VULNERABLE: Public endpoint enabled without restrictions
    endpoint_public_access = true
    public_access_cidrs    = ["0.0.0.0/0"]  # VULNERABLE: Open to world

    # VULNERABLE: Private endpoint disabled
    endpoint_private_access = false
  }

  # VULNERABLE: No logging enabled
  # Missing: enabled_cluster_log_types

  # VULNERABLE: Outdated Kubernetes version
  version = "1.18"  # VULNERABLE: Old version
}
