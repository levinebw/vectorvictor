# Vulnerable AWS EC2 Configuration
# OWASP Cloud Security - Insecure Compute Resources

# VULNERABLE: Security group with open access
resource "aws_security_group" "vulnerable_sg" {
  name        = "vulnerable-security-group"
  description = "Security group with dangerous rules"
  vpc_id      = "vpc-12345678"

  # VULNERABLE: SSH open to the world
  ingress {
    description = "SSH from anywhere"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]  # VULNERABLE: Open to internet
  }

  # VULNERABLE: RDP open to the world
  ingress {
    description = "RDP from anywhere"
    from_port   = 3389
    to_port     = 3389
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]  # VULNERABLE: Open to internet
  }

  # VULNERABLE: All ports open
  ingress {
    description = "All traffic"
    from_port   = 0
    to_port     = 65535
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]  # VULNERABLE: Everything exposed
  }

  # VULNERABLE: Outbound unrestricted
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "Vulnerable SG"
  }
}

# VULNERABLE: EC2 instance with no encryption
resource "aws_instance" "vulnerable_instance" {
  ami           = "ami-0c55b159cbfafe1f0"
  instance_type = "t3.large"

  # VULNERABLE: Using default VPC
  # VULNERABLE: No monitoring enabled
  monitoring = false

  # VULNERABLE: Associated with vulnerable security group
  vpc_security_group_ids = [aws_security_group.vulnerable_sg.id]

  # VULNERABLE: User data with hardcoded credentials
  user_data = <<-EOF
              #!/bin/bash
              export DB_PASSWORD="SuperSecret123!"
              export API_KEY="sk-1234567890abcdef"
              echo "root:Password123!" | chpasswd
              EOF

  # VULNERABLE: No encryption for root volume
  root_block_device {
    encrypted = false  # VULNERABLE: Unencrypted storage
    volume_size = 100
  }

  # VULNERABLE: IMDSv1 enabled (metadata service v1)
  metadata_options {
    http_endpoint               = "enabled"
    http_tokens                 = "optional"  # VULNERABLE: Allows IMDSv1
    http_put_response_hop_limit = 1
  }

  tags = {
    Name = "Vulnerable Instance"
  }
}

# VULNERABLE: EBS volume without encryption
resource "aws_ebs_volume" "unencrypted_volume" {
  availability_zone = "us-west-2a"
  size              = 100

  # VULNERABLE: No encryption
  encrypted = false

  tags = {
    Name = "Unencrypted Volume"
  }
}

# VULNERABLE: Launch template with security issues
resource "aws_launch_template" "vulnerable_template" {
  name_prefix   = "vulnerable-"
  image_id      = "ami-0c55b159cbfafe1f0"
  instance_type = "t3.medium"

  # VULNERABLE: Plaintext secrets in user data
  user_data = base64encode(<<-EOF
    #!/bin/bash
    export AWS_ACCESS_KEY_ID="AKIAIOSFODNN7EXAMPLE"
    export AWS_SECRET_ACCESS_KEY="wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
    EOF
  )

  # VULNERABLE: No encryption
  block_device_mappings {
    device_name = "/dev/sda1"

    ebs {
      volume_size = 20
      encrypted   = false  # VULNERABLE: Unencrypted
    }
  }

  # VULNERABLE: Metadata service not secured
  metadata_options {
    http_tokens = "optional"  # VULNERABLE: IMDSv1 allowed
  }
}

# VULNERABLE: IAM instance profile with overly permissive policy
resource "aws_iam_role" "vulnerable_role" {
  name = "vulnerable-ec2-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "ec2.amazonaws.com"
        }
      },
    ]
  })
}

# VULNERABLE: Policy with admin access
resource "aws_iam_role_policy" "vulnerable_policy" {
  name = "vulnerable-policy"
  role = aws_iam_role.vulnerable_role.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = "*"  # VULNERABLE: All actions allowed
        Resource = "*"  # VULNERABLE: On all resources
      }
    ]
  })
}

# VULNERABLE: Elastic IP without proper tagging/tracking
resource "aws_eip" "untracked_eip" {
  instance = aws_instance.vulnerable_instance.id
  vpc      = true

  # VULNERABLE: No tags for tracking
  # Missing cost allocation and ownership tags
}

# VULNERABLE: Network interface with public IP
resource "aws_network_interface" "vulnerable_eni" {
  subnet_id       = "subnet-12345678"
  security_groups = [aws_security_group.vulnerable_sg.id]

  # VULNERABLE: Source/dest check disabled
  source_dest_check = false

  tags = {
    Name = "Vulnerable ENI"
  }
}
