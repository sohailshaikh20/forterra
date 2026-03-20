"""Security training module — attack scenarios, breach references, and fix code."""

from typing import Dict, Optional

ATTACK_SCENARIOS = {
    "FT-S3-001": {
        "title": "Public S3 Bucket — Data Exposure",
        "attack_scenario": (
            "An attacker uses automated tools like BucketFinder, GrayhatWarfare, "
            "or simple AWS CLI commands to scan for public S3 buckets. Your bucket "
            "shows up in the scan results. The attacker downloads everything — "
            "customer data, backups, config files, secrets. They can do this without "
            "ANY authentication. Public-read means the entire internet can read your data."
        ),
        "real_breaches": [
            {"company": "Capital One", "year": "2019", "impact": "100 million customer records exposed",
             "details": "A misconfigured WAF allowed access to S3 buckets containing credit applications, SSNs, and bank account numbers."},
            {"company": "Twitch", "year": "2021", "impact": "Full source code and creator earnings leaked",
             "details": "An S3 misconfiguration exposed 125GB of data including source code, internal tools, and payment data for all streamers."},
            {"company": "US Military (CENTCOM)", "year": "2017", "impact": "1.8 billion social media surveillance records exposed",
             "details": "Three S3 buckets with no access controls exposed intelligence data collected from social media platforms."},
        ],
        "fix_code": '''# REMOVE this line:
#   acl = "public-read"

# ADD a public access block:
resource "aws_s3_bucket_public_access_block" "BUCKET_NAME" {
  bucket = aws_s3_bucket.BUCKET_NAME.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# Add encryption:
resource "aws_s3_bucket_server_side_encryption_configuration" "BUCKET_NAME" {
  bucket = aws_s3_bucket.BUCKET_NAME.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "aws:kms"
    }
  }
}''',
        "cis_benchmark": "CIS AWS Foundations Benchmark v3.0 — Rule 2.1.1",
        "why_it_matters": "S3 buckets are the #1 source of cloud data breaches. GrayhatWarfare.com indexes millions of public buckets. If your bucket is public, it WILL be found.",
    },
    "FT-S3-002": {
        "title": "Missing S3 Public Access Block",
        "attack_scenario": "Without an explicit public access block, your S3 bucket relies on ACLs and policies alone. A future code change or accidental ACL change could make the bucket public. The public access block is a safety net that OVERRIDES any policy or ACL that tries to make the bucket public.",
        "real_breaches": [
            {"company": "Elasticsearch Servers (multiple)", "year": "2020-2023", "impact": "Billions of records exposed across hundreds of incidents",
             "details": "A recurring pattern of cloud storage left without access blocks, discovered by security researchers and attackers alike."},
        ],
        "fix_code": '''resource "aws_s3_bucket_public_access_block" "BUCKET_NAME" {
  bucket = aws_s3_bucket.BUCKET_NAME.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}''',
        "cis_benchmark": "CIS AWS Foundations Benchmark v3.0 — Rule 2.1.4",
        "why_it_matters": "The public access block is AWS's recommended defense-in-depth measure. It prevents accidental public exposure regardless of individual policies.",
    },
    "FT-SG-001": {
        "title": "Security Group Open to the World (0.0.0.0/0)",
        "attack_scenario": "Your security group allows inbound traffic from ANY IP address. Attackers run automated scanners (Shodan, Masscan, ZMap) that sweep the entire IPv4 space in under an hour. Your open port will be found within minutes. From there, they brute force logins, exploit known vulnerabilities, or use the port as a pivot into your network.",
        "real_breaches": [
            {"company": "MongoDB Instances (mass attack)", "year": "2017", "impact": "28,000 databases wiped and held for ransom",
             "details": "Attackers scanned for MongoDB instances with open security groups, deleted all data, and left ransom notes demanding Bitcoin."},
            {"company": "Tesla", "year": "2018", "impact": "Kubernetes console exposed, used for cryptomining",
             "details": "An unsecured Kubernetes dashboard accessible from 0.0.0.0/0 allowed attackers to deploy cryptominers on Tesla's AWS infrastructure."},
        ],
        "fix_code": '''resource "aws_security_group" "web" {
  name   = "web-sg"
  vpc_id = aws_vpc.main.id

  ingress {
    description     = "HTTPS from load balancer only"
    from_port       = 443
    to_port         = 443
    protocol        = "tcp"
    security_groups = [aws_security_group.alb.id]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}''',
        "cis_benchmark": "CIS AWS Foundations Benchmark v3.0 — Rule 5.2",
        "why_it_matters": "Shodan.io indexes every public IP with open ports. Within minutes of opening a port to 0.0.0.0/0, automated scanners will find it.",
    },
    "FT-SG-002": {
        "title": "SSH (Port 22) Open to the Internet",
        "attack_scenario": "SSH on port 22 open to the internet is one of the most attacked configurations in cloud infrastructure. Attackers run continuous brute-force attacks against every public IP with port 22 open, trying common usernames with password lists containing millions of entries.",
        "real_breaches": [
            {"company": "Alibaba Cloud Instances", "year": "2020", "impact": "Thousands of servers compromised for cryptomining",
             "details": "A botnet called 'Watchdog' exploited open SSH ports to install cryptominers across cloud instances worldwide."},
        ],
        "fix_code": '''# Best: Use AWS SSM Session Manager instead of SSH (no open ports needed)

# If you must use SSH, restrict to your IP:
resource "aws_security_group_rule" "ssh" {
  type              = "ingress"
  from_port         = 22
  to_port           = 22
  protocol          = "tcp"
  cidr_blocks       = ["YOUR.OFFICE.IP/32"]
  security_group_id = aws_security_group.bastion.id
}''',
        "cis_benchmark": "CIS AWS Foundations Benchmark v3.0 — Rule 5.2",
        "why_it_matters": "A single server with SSH open to the internet receives an average of 13,000 brute force login attempts per day. Use SSM Session Manager instead.",
    },
    "FT-RDS-001": {
        "title": "Publicly Accessible Database",
        "attack_scenario": "Your database is directly reachable from the internet. An attacker can connect from anywhere, try default credentials, and exploit known vulnerabilities. If they get in, they have DIRECT access to all your data — no need to hack your application first.",
        "real_breaches": [
            {"company": "Microsoft (Power Apps)", "year": "2021", "impact": "38 million records exposed from 47 organizations",
             "details": "Publicly accessible databases behind Power Apps portals exposed data from American Airlines, Ford, the state of Indiana, and others."},
            {"company": "Facebook", "year": "2019", "impact": "540 million records found on public databases",
             "details": "Third-party apps stored Facebook user data in publicly accessible databases, exposing account names, IDs, and activity."},
        ],
        "fix_code": '''resource "aws_db_instance" "main" {
  publicly_accessible     = false
  db_subnet_group_name    = aws_db_subnet_group.private.name
  storage_encrypted       = true
  backup_retention_period = 14
  deletion_protection     = true
}

resource "aws_db_subnet_group" "private" {
  name       = "private-db-subnets"
  subnet_ids = aws_subnet.private[*].id
}''',
        "cis_benchmark": "CIS AWS Foundations Benchmark v3.0 — Rule 2.3.1",
        "why_it_matters": "A publicly accessible database is one vulnerability away from a complete data breach. Always place databases in private subnets.",
    },
    "FT-RDS-002": {
        "title": "Database Without Encryption at Rest",
        "attack_scenario": "Your database stores data on disk without encryption. If an attacker gains access to the underlying storage — through a snapshot that's shared or a backup that's exposed — they can read all your data in plaintext.",
        "real_breaches": [
            {"company": "Multiple Healthcare Providers", "year": "2019-2023", "impact": "HIPAA violations and millions in fines",
             "details": "Unencrypted databases containing patient health records resulted in regulatory fines when breaches occurred."},
        ],
        "fix_code": '''resource "aws_db_instance" "main" {
  storage_encrypted = true
  kms_key_id        = aws_kms_key.rds.arn
}

resource "aws_kms_key" "rds" {
  description         = "KMS key for RDS encryption"
  enable_key_rotation = true
}''',
        "cis_benchmark": "CIS AWS Foundations Benchmark v3.0 — Rule 2.3.1",
        "why_it_matters": "Encryption at rest is a baseline requirement for SOC2, HIPAA, PCI-DSS, and GDPR. It's free in AWS — no reason not to enable it.",
    },
    "FT-IAM-001": {
        "title": "IAM Policy with Wildcard Permissions",
        "attack_scenario": "This IAM policy grants FULL access to EVERYTHING in your AWS account. If any service or user with this policy is compromised, the attacker can delete all resources, access all data, create new admin users, change billing, and cover their tracks by deleting CloudTrail logs.",
        "real_breaches": [
            {"company": "Uber", "year": "2016", "impact": "57 million user records stolen",
             "details": "Attackers found AWS credentials with broad permissions in a GitHub repo. The overly permissive IAM policies let them access S3 buckets with rider and driver data."},
            {"company": "SolarWinds", "year": "2020", "impact": "18,000 organizations compromised including US government",
             "details": "Compromised credentials with broad cloud permissions allowed attackers to move laterally through government and enterprise cloud environments."},
        ],
        "fix_code": '''resource "aws_iam_policy" "app_policy" {
  name = "app-limited-policy"
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = ["s3:GetObject", "s3:PutObject"]
        Resource = ["arn:aws:s3:::my-app-bucket/*"]
      },
      {
        Effect   = "Allow"
        Action   = ["logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents"]
        Resource = "arn:aws:logs:*:*:*"
      }
    ]
  })
}''',
        "cis_benchmark": "CIS AWS Foundations Benchmark v3.0 — Rule 1.16",
        "why_it_matters": "IAM misconfigurations are the #1 cause of cloud security breaches. Every resource should have scoped permissions — never use wildcard (*).",
    },
    "FT-SEC-001": {
        "title": "Hardcoded Secrets in Terraform Code",
        "attack_scenario": "Your Terraform code contains a plaintext password or secret. When pushed to Git, the secret is permanently in commit history — even if deleted later. Tools like TruffleHog and GitLeaks constantly scan repos for exposed credentials.",
        "real_breaches": [
            {"company": "Uber", "year": "2016", "impact": "AWS credentials in GitHub repo led to 57M record breach",
             "details": "Developers committed AWS access keys to a private GitHub repository. Attackers gained access and used the keys to exfiltrate data."},
            {"company": "Samsung", "year": "2022", "impact": "Secret keys exposed in public GitLab repos",
             "details": "Researchers found Samsung employees had committed AWS keys, GitHub tokens, and internal credentials to public repositories."},
        ],
        "fix_code": '''# Use AWS Secrets Manager:
data "aws_secretsmanager_secret_version" "db_password" {
  secret_id = "prod/database/password"
}

resource "aws_db_instance" "main" {
  password = data.aws_secretsmanager_secret_version.db_password.secret_string
}

# Or use variables with sensitive flag:
variable "db_password" {
  type      = string
  sensitive = true
}
# Set via: TF_VAR_db_password=xxx terraform apply''',
        "cis_benchmark": "CIS AWS Foundations Benchmark v3.0 — Credential management rules",
        "why_it_matters": "Over 100 million secrets were pushed to public repos in 2024. Once in Git history, it's effectively permanent. Always use a secrets manager.",
    },
    "FT-EKS-001": {
        "title": "EKS Cluster API Endpoint Public",
        "attack_scenario": "Your Kubernetes API server is accessible from the internet. Anyone can attempt to authenticate. A Kubernetes vulnerability, misconfigured RBAC, or leaked kubeconfig lets attackers access your cluster from anywhere.",
        "real_breaches": [
            {"company": "Tesla", "year": "2018", "impact": "Kubernetes console exposed, cryptomining deployed",
             "details": "An unsecured Kubernetes dashboard was accessible from the internet, allowing attackers to deploy cryptominers on Tesla's cloud."},
        ],
        "fix_code": '''resource "aws_eks_cluster" "main" {
  name     = "production"
  role_arn = aws_iam_role.eks.arn

  vpc_config {
    endpoint_private_access = true
    endpoint_public_access  = false
    subnet_ids              = aws_subnet.private[*].id
  }
}''',
        "cis_benchmark": "CIS Amazon EKS Benchmark v1.4 — Rule 5.4.1",
        "why_it_matters": "A public Kubernetes API is a direct path into your cluster. Use a VPN or private endpoint.",
    },
}


def get_scenario(rule_id: str) -> Optional[Dict]:
    return ATTACK_SCENARIOS.get(rule_id)


def get_all_scenarios() -> Dict:
    return ATTACK_SCENARIOS


def format_breach(breach: Dict) -> str:
    return f"{breach['company']} ({breach['year']}) — {breach['impact']}"
