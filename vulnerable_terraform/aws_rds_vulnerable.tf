# Vulnerable AWS RDS Configuration
# OWASP Cloud Security - Insecure Database Configuration

# VULNERABLE: RDS instance with public access
resource "aws_db_instance" "vulnerable_database" {
  identifier           = "vulnerable-database"
  engine               = "mysql"
  engine_version       = "5.7"  # VULNERABLE: Outdated version
  instance_class       = "db.t3.micro"
  allocated_storage    = 20

  # VULNERABLE: Hardcoded credentials
  username = "admin"
  password = "Password123!"  # VULNERABLE: Weak password in plain text

  # VULNERABLE: Publicly accessible
  publicly_accessible = true

  # VULNERABLE: No encryption
  storage_encrypted = false

  # VULNERABLE: No automatic backups
  backup_retention_period = 0

  # VULNERABLE: Skip final snapshot
  skip_final_snapshot = true

  # VULNERABLE: No deletion protection
  deletion_protection = false

  # VULNERABLE: Auto minor version upgrade disabled
  auto_minor_version_upgrade = false

  # VULNERABLE: No enhanced monitoring
  monitoring_interval = 0

  # VULNERABLE: Logs not enabled
  enabled_cloudwatch_logs_exports = []

  # VULNERABLE: Default security group (overly permissive)
  vpc_security_group_ids = ["sg-12345678"]

  # VULNERABLE: Default parameter group (insecure settings)
  parameter_group_name = "default.mysql5.7"

  # VULNERABLE: Multi-AZ disabled (no HA)
  multi_az = false

  tags = {
    Name = "Vulnerable Database"
  }
}

# VULNERABLE: DB subnet group in public subnets
resource "aws_db_subnet_group" "vulnerable_subnet_group" {
  name       = "vulnerable-db-subnet"
  subnet_ids = ["subnet-public1", "subnet-public2"]  # VULNERABLE: Public subnets

  tags = {
    Name = "Vulnerable DB Subnet Group"
  }
}

# VULNERABLE: RDS parameter group with insecure settings
resource "aws_db_parameter_group" "vulnerable_params" {
  name   = "vulnerable-mysql-params"
  family = "mysql5.7"

  # VULNERABLE: SSL not required
  parameter {
    name  = "require_secure_transport"
    value = "0"  # VULNERABLE: Allows unencrypted connections
  }

  # VULNERABLE: Weak password policy
  parameter {
    name  = "validate_password_length"
    value = "4"  # VULNERABLE: Min password length too short
  }

  # VULNERABLE: Query logging disabled
  parameter {
    name  = "general_log"
    value = "0"
  }

  # VULNERABLE: Slow query log disabled
  parameter {
    name  = "slow_query_log"
    value = "0"
  }
}

# VULNERABLE: PostgreSQL with dangerous settings
resource "aws_db_instance" "vulnerable_postgres" {
  identifier        = "vulnerable-postgres"
  engine            = "postgres"
  engine_version    = "10.0"  # VULNERABLE: Very outdated version
  instance_class    = "db.t3.micro"
  allocated_storage = 20

  # VULNERABLE: Default credentials
  username = "postgres"
  password = "postgres"  # VULNERABLE: Default password

  # VULNERABLE: Public access
  publicly_accessible = true

  # VULNERABLE: No encryption at rest
  storage_encrypted = false

  # VULNERABLE: No backups
  backup_retention_period = 0
  skip_final_snapshot     = true

  # VULNERABLE: Performance insights disabled
  performance_insights_enabled = false

  # VULNERABLE: No IAM authentication
  iam_database_authentication_enabled = false

  tags = {
    Name = "Vulnerable PostgreSQL"
  }
}

# VULNERABLE: Aurora cluster without encryption
resource "aws_rds_cluster" "vulnerable_aurora" {
  cluster_identifier = "vulnerable-aurora-cluster"
  engine             = "aurora-mysql"
  engine_version     = "5.7.mysql_aurora.2.04.0"  # VULNERABLE: Old version

  # VULNERABLE: Hardcoded master credentials
  master_username = "admin"
  master_password = "AuroraPassword123!"

  # VULNERABLE: No encryption
  storage_encrypted = false

  # VULNERABLE: Backups disabled
  backup_retention_period = 0
  skip_final_snapshot     = true

  # VULNERABLE: No deletion protection
  deletion_protection = false

  # VULNERABLE: Default VPC
  db_subnet_group_name = "default"

  # VULNERABLE: No CloudWatch logs
  enabled_cloudwatch_logs_exports = []

  tags = {
    Name = "Vulnerable Aurora"
  }
}

# VULNERABLE: DB snapshot with public sharing
resource "aws_db_snapshot" "vulnerable_snapshot" {
  db_instance_identifier = aws_db_instance.vulnerable_database.id
  db_snapshot_identifier = "vulnerable-snapshot"

  tags = {
    Name = "Vulnerable Snapshot"
  }
}

# VULNERABLE: Sharing snapshot publicly
resource "aws_db_snapshot_copy" "public_snapshot" {
  source_db_snapshot_identifier = aws_db_snapshot.vulnerable_snapshot.id
  target_db_snapshot_identifier = "public-snapshot-copy"

  # VULNERABLE: Could be shared publicly via CLI/API
  # Missing: proper access controls

  tags = {
    Name = "Public Snapshot Copy"
  }
}

# VULNERABLE: RDS proxy without TLS requirement
resource "aws_db_proxy" "vulnerable_proxy" {
  name                   = "vulnerable-db-proxy"
  engine_family          = "MYSQL"
  auth {
    auth_scheme = "SECRETS"
    iam_auth    = "DISABLED"  # VULNERABLE: IAM auth disabled
    secret_arn  = "arn:aws:secretsmanager:us-west-2:123456789012:secret:db-secret"
  }

  role_arn               = "arn:aws:iam::123456789012:role/db-proxy-role"
  vpc_subnet_ids         = ["subnet-12345678", "subnet-87654321"]

  # VULNERABLE: TLS not required
  require_tls = false

  tags = {
    Name = "Vulnerable DB Proxy"
  }
}
