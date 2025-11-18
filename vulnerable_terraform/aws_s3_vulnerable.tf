# Vulnerable AWS S3 Bucket Configuration
# OWASP Cloud Security - Insecure Storage

# VULNERABLE: S3 bucket with public access
resource "aws_s3_bucket" "vulnerable_public_bucket" {
  bucket = "my-vulnerable-public-bucket"

  # VULNERABLE: Public ACL allowing anyone to read
  acl = "public-read"

  tags = {
    Name        = "Vulnerable Public Bucket"
    Environment = "Demo"
  }
}

# VULNERABLE: S3 bucket without encryption
resource "aws_s3_bucket" "unencrypted_bucket" {
  bucket = "my-unencrypted-bucket"

  # VULNERABLE: No server-side encryption configured
  # Missing: server_side_encryption_configuration

  versioning {
    enabled = false  # VULNERABLE: Versioning disabled
  }

  tags = {
    Name = "Unencrypted Bucket"
  }
}

# VULNERABLE: S3 bucket with public access block disabled
resource "aws_s3_bucket_public_access_block" "vulnerable_access" {
  bucket = aws_s3_bucket.vulnerable_public_bucket.id

  # VULNERABLE: All public access controls disabled
  block_public_acls       = false
  block_public_policy     = false
  ignore_public_acls      = false
  restrict_public_buckets = false
}

# VULNERABLE: S3 bucket policy allowing public access
resource "aws_s3_bucket_policy" "allow_public_access" {
  bucket = aws_s3_bucket.vulnerable_public_bucket.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "PublicReadGetObject"
        Effect    = "Allow"
        Principal = "*"  # VULNERABLE: Allows anyone
        Action    = "s3:GetObject"
        Resource = [
          "${aws_s3_bucket.vulnerable_public_bucket.arn}/*",
        ]
      },
      {
        # VULNERABLE: Public write access
        Sid       = "PublicWrite"
        Effect    = "Allow"
        Principal = "*"
        Action = [
          "s3:PutObject",
          "s3:DeleteObject"
        ]
        Resource = "${aws_s3_bucket.vulnerable_public_bucket.arn}/*"
      }
    ]
  })
}

# VULNERABLE: S3 bucket without logging
resource "aws_s3_bucket" "no_logging_bucket" {
  bucket = "bucket-without-logging"

  # VULNERABLE: No logging configuration
  # Missing: logging block

  tags = {
    Name = "No Logging Bucket"
  }
}

# VULNERABLE: S3 bucket without versioning or MFA delete
resource "aws_s3_bucket" "no_protection_bucket" {
  bucket = "bucket-no-protection"

  versioning {
    enabled    = false  # VULNERABLE: No versioning
    mfa_delete = false  # VULNERABLE: No MFA for delete
  }

  tags = {
    Name = "Unprotected Bucket"
  }
}

# VULNERABLE: Bucket with overly permissive CORS
resource "aws_s3_bucket_cors_configuration" "vulnerable_cors" {
  bucket = aws_s3_bucket.vulnerable_public_bucket.id

  cors_rule {
    allowed_headers = ["*"]  # VULNERABLE: All headers allowed
    allowed_methods = ["GET", "PUT", "POST", "DELETE"]  # VULNERABLE: All methods
    allowed_origins = ["*"]  # VULNERABLE: All origins allowed
    expose_headers  = ["ETag"]
    max_age_seconds = 3000
  }
}

# VULNERABLE: Lifecycle rule that deletes data too quickly
resource "aws_s3_bucket_lifecycle_configuration" "vulnerable_lifecycle" {
  bucket = aws_s3_bucket.no_protection_bucket.id

  rule {
    id     = "delete-old-data"
    status = "Enabled"

    expiration {
      days = 1  # VULNERABLE: Deletes data after just 1 day
    }
  }
}
