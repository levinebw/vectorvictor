# Vulnerable Terraform Configurations - Security Scanner Demo

⚠️ **WARNING**: These Terraform configurations contain intentional security vulnerabilities and misconfigurations. **NEVER** apply these to any AWS account. For testing and educational purposes only!

## Purpose

This collection demonstrates common Infrastructure as Code (IaC) security vulnerabilities found in Terraform configurations. Use these examples to test:
- Terraform security scanners (tfsec, Checkov, Terrascan, etc.)
- Cloud security posture management (CSPM) tools
- Custom static analysis tools
- Security training and education

## Vulnerability Categories

### 1. S3 Storage Security (`aws_s3_vulnerable.tf`)

**Vulnerabilities:**
- Public read/write ACLs on S3 buckets
- No encryption at rest
- Public access block disabled
- Wildcard principals in bucket policies
- Missing logging configuration
- No versioning or MFA delete
- Overly permissive CORS configuration
- Dangerous lifecycle policies

**Example Issues:**
```hcl
# Public bucket
acl = "public-read"

# No encryption
# Missing: server_side_encryption_configuration

# Public access enabled
block_public_acls = false
```

### 2. EC2 Compute Security (`aws_ec2_vulnerable.tf`)

**Vulnerabilities:**
- Security groups open to 0.0.0.0/0
- SSH (22) and RDP (3389) exposed to internet
- All ports open
- Unencrypted EBS volumes
- IMDSv1 enabled (metadata service vulnerability)
- Hardcoded credentials in user data
- IAM roles with admin access
- No monitoring enabled
- Unencrypted root volumes

**Example Issues:**
```hcl
# Open SSH to world
cidr_blocks = ["0.0.0.0/0"]

# Hardcoded secrets in user data
user_data = <<-EOF
  export DB_PASSWORD="SuperSecret123!"
EOF

# IMDSv1 enabled
http_tokens = "optional"
```

### 3. RDS Database Security (`aws_rds_vulnerable.tf`)

**Vulnerabilities:**
- Publicly accessible databases
- Hardcoded passwords in plain text
- No encryption at rest
- Outdated database versions
- No automatic backups
- Skip final snapshot enabled
- No deletion protection
- SSL/TLS not required
- No CloudWatch logging
- Weak password policies
- Multi-AZ disabled

**Example Issues:**
```hcl
# Public database
publicly_accessible = true

# Plain text password
password = "Password123!"

# No encryption
storage_encrypted = false

# No backups
backup_retention_period = 0
```

### 4. IAM Security (`aws_iam_vulnerable.tf`)

**Vulnerabilities:**
- Long-term access keys for users
- Overly permissive policies (Action: "*", Resource: "*")
- Wildcard principals in trust policies
- No MFA requirements
- Weak password policies
- Privilege escalation paths
- Cross-account access without conditions
- AWS managed policies that are too broad
- NotAction statements (inverse logic)
- Assume role on any resource

**Example Issues:**
```hcl
# Admin access
Action = "*"
Resource = "*"

# Wildcard principal
Principal = {
  AWS = "*"
}

# Weak password policy
minimum_password_length = 6
require_symbols = false
max_password_age = 0
```

### 5. Miscellaneous Services (`aws_misc_vulnerable.tf`)

**Services Covered:**
- CloudFront (HTTP only, old TLS, no WAF)
- Lambda (hardcoded secrets, outdated runtime, no VPC)
- API Gateway (no authentication, no throttling)
- SNS/SQS (public access, no encryption)
- Secrets Manager (no rotation, hardcoded values)
- KMS (overly permissive, no rotation)
- CloudWatch (no encryption, short retention)
- Elasticsearch (no encryption, outdated, public)
- EKS (public endpoint, no logging, old version)

**Example Issues:**
```hcl
# Lambda with hardcoded secrets
environment {
  variables = {
    DB_PASSWORD = "SuperSecret123!"
    API_KEY = "sk-1234567890"
  }
}

# API Gateway without auth
authorization = "NONE"

# Public SNS/SQS
Principal = "*"
```

## Security Scanner Testing

### Expected Detections

Your security scanner should detect at least:

| Category | Vulnerability Count |
|----------|-------------------|
| S3 Security | 15+ issues |
| EC2 Security | 20+ issues |
| RDS Security | 25+ issues |
| IAM Security | 15+ issues |
| Network Security | 10+ issues |
| Encryption | 20+ issues |
| Logging & Monitoring | 10+ issues |
| Secrets Management | 15+ issues |

### Testing with Common Tools

#### tfsec
```bash
tfsec vulnerable_terraform/
```

#### Checkov
```bash
checkov -d vulnerable_terraform/
```

#### Terrascan
```bash
terrascan scan -t aws -d vulnerable_terraform/
```

#### TFLint
```bash
tflint vulnerable_terraform/
```

#### Snyk IaC
```bash
snyk iac test vulnerable_terraform/
```

## Vulnerability Reference

### CIS AWS Foundations Benchmark Violations

- 1.x - IAM violations (weak passwords, no MFA, overly permissive)
- 2.x - Storage violations (unencrypted S3, public access)
- 3.x - Logging violations (CloudTrail, VPC Flow Logs missing)
- 4.x - Monitoring violations (no CloudWatch alarms)
- 5.x - Networking violations (security groups, NACLs)

### OWASP Cloud Security Top 10

- **CS1**: Insufficient Identity and Access Management
- **CS2**: Insufficient Logging and Monitoring
- **CS3**: Insecure Network Configuration
- **CS4**: Insecure Data Storage
- **CS5**: Insecure Secrets Management
- **CS6**: Vulnerable and Outdated Components
- **CS7**: Insecure Default Configurations
- **CS8**: Missing Encryption
- **CS9**: Improper Asset Management
- **CS10**: Inadequate Security Awareness

### Common Misconfigurations

1. **Hardcoded Credentials**: Never put passwords, API keys, or access keys in Terraform
2. **Public Access**: Default to private; explicitly allow public only when necessary
3. **Missing Encryption**: Encrypt data at rest and in transit
4. **Overly Permissive IAM**: Follow least privilege principle
5. **No Logging**: Enable logging for all resources
6. **Outdated Versions**: Use latest stable versions
7. **No Backup/Recovery**: Enable backups and set retention policies
8. **Missing Network Controls**: Use VPCs, security groups properly
9. **Wildcard Principals**: Never use "*" in IAM policies without conditions
10. **Disabled Security Features**: Enable MFA, versioning, deletion protection

## Security Best Practices

### ✅ Do This Instead

```hcl
# Secure S3 bucket
resource "aws_s3_bucket" "secure" {
  bucket = "secure-bucket"
  acl    = "private"
}

resource "aws_s3_bucket_server_side_encryption_configuration" "secure" {
  bucket = aws_s3_bucket.secure.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "aws:kms"
      kms_master_key_id = aws_kms_key.secure.arn
    }
  }
}

resource "aws_s3_bucket_public_access_block" "secure" {
  bucket = aws_s3_bucket.secure.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# Secure RDS
resource "aws_db_instance" "secure" {
  identifier     = "secure-db"
  engine         = "postgres"
  engine_version = "15.3"  # Latest stable

  storage_encrypted = true
  kms_key_id       = aws_kms_key.secure.arn

  # Use AWS Secrets Manager
  username = jsondecode(data.aws_secretsmanager_secret_version.db.secret_string)["username"]
  password = jsondecode(data.aws_secretsmanager_secret_version.db.secret_string)["password"]

  publicly_accessible    = false
  deletion_protection    = true
  backup_retention_period = 30

  enabled_cloudwatch_logs_exports = ["postgresql", "upgrade"]
}

# Secure IAM
resource "aws_iam_policy" "secure" {
  name = "secure-policy"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Action = [
        "s3:GetObject",
        "s3:PutObject"
      ]
      Resource = "arn:aws:s3:::specific-bucket/specific-prefix/*"
    }]
  })
}
```

## Tools and Integration

### Pre-commit Hooks
```bash
# Install pre-commit
pip install pre-commit

# .pre-commit-config.yaml
repos:
  - repo: https://github.com/antonbabenko/pre-commit-terraform
    hooks:
      - id: terraform_tfsec
      - id: terraform_checkov
```

### CI/CD Integration
```yaml
# GitHub Actions example
- name: Run tfsec
  uses: aquasecurity/tfsec-action@v1.0.0

- name: Run Checkov
  uses: bridgecrewio/checkov-action@master
```

## Compliance Frameworks

These vulnerabilities violate multiple compliance frameworks:
- PCI DSS
- HIPAA
- SOC 2
- ISO 27001
- GDPR
- CIS Benchmarks
- NIST 800-53

## Contributing

To add more vulnerable examples:
1. Follow the existing pattern
2. Add clear "VULNERABLE" comments
3. Include the specific security issue
4. Reference CWE or CVE when applicable
5. Update this README

## Disclaimer

⚠️ **DO NOT APPLY THESE CONFIGURATIONS**

These Terraform files are intentionally vulnerable and should only be used for:
- Testing security scanning tools
- Security training and education
- Demonstrating security best practices (what NOT to do)
- Security research in isolated environments

Applying these configurations to any AWS account will create serious security vulnerabilities. The authors are not responsible for any security incidents resulting from misuse of these examples.

## License

Educational use only. See LICENSE file.
