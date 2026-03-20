# ============================================================
# 🚨 INTENTIONALLY INSECURE TERRAFORM — FOR TESTING FORTERRA
# DO NOT deploy this. Run: forterra learn ./examples/
# ============================================================

terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
  # Missing required_version — FT-GEN-001
}

provider "aws" {
  region = "us-east-1"
}

# ❌ Public S3 bucket — FT-S3-001
resource "aws_s3_bucket" "data" {
  bucket = "my-company-data-store"
  acl    = "public-read"  # CRITICAL: Anyone on the internet can read this
}
# Missing: aws_s3_bucket_public_access_block — FT-S3-002
# Missing: aws_s3_bucket_server_side_encryption_configuration — FT-S3-003

# ❌ Security group open to the world — FT-SG-001
resource "aws_security_group" "web" {
  name   = "web-sg"
  vpc_id = "vpc-12345"

  ingress {
    from_port   = 0
    to_port     = 65535
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]  # CRITICAL: All ports open to entire internet
  }
}

# ❌ SSH open to the world — FT-SG-002
resource "aws_security_group_rule" "ssh" {
  type              = "ingress"
  from_port         = 22
  to_port           = 22
  protocol          = "tcp"
  cidr_blocks       = ["0.0.0.0/0"]  # HIGH: SSH open to entire internet
  security_group_id = aws_security_group.web.id
}

# ❌ Publicly accessible database — FT-RDS-001
resource "aws_db_instance" "production" {
  identifier          = "prod-database"
  engine              = "postgres"
  engine_version      = "15.4"
  instance_class      = "db.t3.medium"
  allocated_storage   = 100
  publicly_accessible = true         # CRITICAL: Database on the internet
  storage_encrypted   = false        # HIGH: No encryption at rest — FT-RDS-002
  backup_retention_period = 0        # MEDIUM: No backups — FT-RDS-003

  # ❌ Hardcoded password — FT-SEC-001
  password = "super_secret_db_password_123"
  username = "admin"
}

# ❌ IAM policy with wildcard permissions — FT-IAM-001
resource "aws_iam_policy" "app_policy" {
  name = "app-full-access"
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = "*"
        Resource = "*"
      }
    ]
  })
}

# ❌ EC2 with public IP — FT-EC2-001
resource "aws_instance" "web" {
  ami                         = "ami-0c55b159cbfafe1f0"
  instance_class              = "t3.micro"
  associate_public_ip_address = true  # MEDIUM: Direct public IP
}

# ❌ EKS with public API — FT-EKS-001
resource "aws_eks_cluster" "main" {
  name     = "production-cluster"
  role_arn = aws_iam_role.eks.arn

  vpc_config {
    endpoint_public_access  = true   # HIGH: K8s API on the internet
    endpoint_private_access = false
  }
}
