# Terraform Configuration with IaC Security Vulnerabilities
# This file contains intentional security misconfigurations for testing

terraform {
  required_version = ">= 0.12"
  
  # Vulnerability 1: No backend encryption configured
  backend "s3" {
    bucket = "terraform-state"
    key    = "prod/terraform.tfstate"
    region = "us-east-1"
    # Missing: encrypt = true
    # Missing: kms_key_id
  }
}

provider "aws" {
  region = "us-east-1"
  
  # Vulnerability 2: Hardcoded credentials
  access_key = "AKIAIOSFODNN7EXAMPLE"
  secret_key = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
}

# Vulnerability 3: S3 bucket with public access
resource "aws_s3_bucket" "public_bucket" {
  bucket = "my-public-bucket-12345"
  
  # Vulnerability 4: No encryption
  # Missing: server_side_encryption_configuration
  
  # Vulnerability 5: No versioning
  # Missing: versioning
  
  # Vulnerability 6: No logging
  # Missing: logging
}

resource "aws_s3_bucket_acl" "public_bucket_acl" {
  bucket = aws_s3_bucket.public_bucket.id
  acl    = "public-read"  # Everyone can read
}

resource "aws_s3_bucket_public_access_block" "public_bucket_pab" {
  bucket = aws_s3_bucket.public_bucket.id
  
  # Vulnerability 7: Public access enabled
  block_public_acls       = false
  block_public_policy     = false
  ignore_public_acls      = false
  restrict_public_buckets = false
}

# Vulnerability 8: Security group with unrestricted access
resource "aws_security_group" "allow_all" {
  name        = "allow_all_traffic"
  description = "Allow all inbound traffic"
  vpc_id      = aws_vpc.main.id

  ingress {
    description = "Allow all traffic"
    from_port   = 0
    to_port     = 65535
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]  # Open to the world
  }

  ingress {
    description = "SSH from anywhere"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    description = "RDP from anywhere"
    from_port   = 3389
    to_port     = 3389
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

# Vulnerability 9: EC2 instance with insecure configuration
resource "aws_instance" "vulnerable_instance" {
  ami           = "ami-0c55b159cbfafe1f0"
  instance_type = "t2.micro"
  
  # Vulnerability 10: No encryption for EBS volumes
  # Missing: ebs_block_device with encrypted = true
  
  # Vulnerability 11: Public IP address
  associate_public_ip_address = true
  
  # Vulnerability 12: Weak security group
  vpc_security_group_ids = [aws_security_group.allow_all.id]
  
  # Vulnerability 13: No monitoring
  monitoring = false
  
  # Vulnerability 14: User data with secrets
  user_data = <<-EOF
              #!/bin/bash
              export DATABASE_PASSWORD="SuperSecretPassword123"
              export API_KEY="sk-1234567890abcdef"
              echo "root:password" | chpasswd
              EOF
  
  # Vulnerability 15: No IAM instance profile
  # Missing: iam_instance_profile
  
  tags = {
    Name = "Vulnerable Instance"
  }
}

# Vulnerability 16: RDS database with weak settings
resource "aws_db_instance" "vulnerable_db" {
  identifier = "vulnerable-database"
  
  engine         = "mysql"
  engine_version = "5.7"
  instance_class = "db.t2.micro"
  
  # Vulnerability 17: Weak credentials
  username = "admin"
  password = "password123"
  
  # Vulnerability 18: Publicly accessible
  publicly_accessible = true
  
  # Vulnerability 19: No encryption
  storage_encrypted = false
  
  # Vulnerability 20: No backup retention
  backup_retention_period = 0
  
  # Vulnerability 21: Disabled automated backups
  skip_final_snapshot = true
  
  # Vulnerability 22: Insecure security group
  vpc_security_group_ids = [aws_security_group.allow_all.id]
  
  # Vulnerability 23: No multi-AZ deployment
  multi_az = false
  
  # Vulnerability 24: No deletion protection
  deletion_protection = false
  
  # Vulnerability 25: No enhanced monitoring
  enabled_cloudwatch_logs_exports = []
}

# Vulnerability 26: IAM user with hardcoded credentials
resource "aws_iam_user" "vulnerable_user" {
  name = "vulnerable-user"
}

resource "aws_iam_access_key" "vulnerable_key" {
  user = aws_iam_user.vulnerable_user.name
}

# Vulnerability 27: Overly permissive IAM policy
resource "aws_iam_policy" "admin_policy" {
  name = "admin-policy"
  
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = "*"
        Resource = "*"
      }
    ]
  })
}

resource "aws_iam_user_policy_attachment" "vulnerable_attach" {
  user       = aws_iam_user.vulnerable_user.name
  policy_arn = aws_iam_policy.admin_policy.arn
}

# Vulnerability 28: ELB without HTTPS
resource "aws_elb" "vulnerable_elb" {
  name               = "vulnerable-elb"
  availability_zones = ["us-east-1a", "us-east-1b"]

  listener {
    instance_port     = 8000
    instance_protocol = "http"
    lb_port           = 80
    lb_protocol       = "http"  # No HTTPS
  }

  # Vulnerability 29: No access logs
  # Missing: access_logs configuration
  
  # Vulnerability 30: No connection draining
  # Missing: connection_draining
}

# VPC configuration
resource "aws_vpc" "main" {
  cidr_block = "10.0.0.0/16"
  
  # Vulnerability 31: No flow logs
  # Missing: aws_flow_log
}

# Vulnerability 32: Lambda function with environment secrets
resource "aws_lambda_function" "vulnerable_lambda" {
  filename      = "lambda.zip"
  function_name = "vulnerable_function"
  role          = aws_iam_role.lambda_role.arn
  handler       = "index.handler"
  runtime       = "python3.8"
  
  environment {
    variables = {
      DATABASE_PASSWORD = "SuperSecretPassword123"
      API_KEY          = "sk-1234567890abcdef"
    }
  }
  
  # Vulnerability 33: No VPC configuration (public internet access)
  # Missing: vpc_config
  
  # Vulnerability 34: No tracing
  # Missing: tracing_config
}

resource "aws_iam_role" "lambda_role" {
  name = "lambda_role"
  
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "lambda.amazonaws.com"
        }
      }
    ]
  })
}

# Vulnerability 35: CloudFront distribution without WAF
resource "aws_cloudfront_distribution" "vulnerable_cf" {
  origin {
    domain_name = aws_s3_bucket.public_bucket.bucket_regional_domain_name
    origin_id   = "S3-vulnerable"
  }

  enabled = true

  default_cache_behavior {
    allowed_methods  = ["GET", "HEAD", "OPTIONS", "PUT", "POST", "PATCH", "DELETE"]
    cached_methods   = ["GET", "HEAD"]
    target_origin_id = "S3-vulnerable"

    forwarded_values {
      query_string = false
      cookies {
        forward = "none"
      }
    }

    viewer_protocol_policy = "allow-all"  # Allows HTTP
  }

  restrictions {
    geo_restriction {
      restriction_type = "none"
    }
  }

  viewer_certificate {
    cloudfront_default_certificate = true  # No custom SSL
  }
  
  # Vulnerability 36: No WAF association
  # Missing: web_acl_id
  
  # Vulnerability 37: No logging
  # Missing: logging_config
}

# Output sensitive information
output "database_password" {
  value = aws_db_instance.vulnerable_db.password
  # Vulnerability 38: Sensitive output not marked as sensitive
  # Missing: sensitive = true
}

output "access_key" {
  value = aws_iam_access_key.vulnerable_key.id
}

output "secret_key" {
  value = aws_iam_access_key.vulnerable_key.secret
}
