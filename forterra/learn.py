"""
Learn Module — Teaches Terraform security through real attack scenarios.

HOW THIS WORKS:
- Scans .tf files for security issues (like the scanner)
- But instead of just saying "this is wrong", it teaches you:
  1. The ATTACK SCENARIO — how a hacker would exploit this
  2. The REAL-WORLD BREACH — an actual incident caused by this issue
  3. The FIX — exact code to fix it with explanation
  4. The CIS BENCHMARK — which compliance rule this violates

This is what makes Forterra unique. Checkov says "FAILED: CKV_AWS_18".
Forterra says "An attacker could use bucket-finder to find your public
bucket and download all your customer data. This is what happened to
Capital One in 2019 (100M records exposed)."

YOU CAN MODIFY:
- Add new entries to ATTACK_SCENARIOS for more rules
- Add more real-world breaches
- Change the explanation style
"""

from typing import Dict, List, Optional


# ============================================================
# ATTACK SCENARIOS DATABASE
#
# Each entry maps a security rule ID to a rich educational scenario.
# These are the core of the "learn" feature.
#
# To add a new scenario:
#   1. Add a rule in scanner.py (SECURITY_RULES)
#   2. Add a matching entry here with the same rule ID
# ============================================================
ATTACK_SCENARIOS = {
    "FT-S3-001": {
        "title": "Public S3 Bucket — Data Exposure",
        "attack_scenario": (
            "An attacker uses automated tools like BucketFinder, GrayhatWarfare, "
            "or even simple AWS CLI commands to scan for public S3 buckets. Your "
            "bucket shows up in the scan results. The attacker downloads everything — "
            "customer data, backups, config files, secrets. They can do this without "
            "ANY authentication. Public-read means the entire internet can read your data."
        ),
        "real_breaches": [
            {
                "company": "Capital One",
                "year": "2019",
                "impact": "100 million customer records exposed",
                "details": "A misconfigured WAF allowed access to S3 buckets containing credit applications, SSNs, and bank account numbers.",
            },
            {
                "company": "Twitch",
                "year": "2021",
                "impact": "Full source code and creator earnings leaked",
                "details": "An S3 misconfiguration exposed 125GB of data including source code, internal tools, and payment data for all streamers.",
            },
            {
                "company": "US Military (CENTCOM)",
                "year": "2017",
                "impact": "1.8 billion social media surveillance records exposed",
                "details": "Three S3 buckets with no access controls exposed intelligence data collected from social media platforms.",
            },
        ],
        "fix_code": '''# REMOVE this line:
#   acl = "public-read"

# ADD a public access block (best practice):
resource "aws_s3_bucket_public_access_block" "BUCKET_NAME" {
  bucket = aws_s3_bucket.BUCKET_NAME.id

  block_public_acls       = true   # Block public ACLs
  block_public_policy     = true   # Block public bucket policies
  ignore_public_acls      = true   # Ignore any existing public ACLs
  restrict_public_buckets = true   # Restrict public bucket access
}

# Also add encryption:
resource "aws_s3_bucket_server_side_encryption_configuration" "BUCKET_NAME" {
  bucket = aws_s3_bucket.BUCKET_NAME.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "aws:kms"    # Use KMS for encryption at rest
    }
  }
}''',
        "cis_benchmark": "CIS AWS Foundations Benchmark v3.0 — Rule 2.1.1: Ensure S3 bucket policy is set to deny HTTP requests",
        "why_it_matters": (
            "S3 buckets are the #1 source of cloud data breaches. GrayhatWarfare.com "
            "indexes millions of public buckets. If your bucket is public, it WILL be found."
        ),
    },

    "FT-S3-002": {
        "title": "Missing S3 Public Access Block",
        "attack_scenario": (
            "Without an explicit public access block, your S3 bucket relies on ACLs and "
            "policies alone for access control. A future code change, a misconfigured "
            "policy, or an accidental ACL change could make the bucket public. The public "
            "access block is a safety net — a last line of defense that OVERRIDES any "
            "policy or ACL that tries to make the bucket public."
        ),
        "real_breaches": [
            {
                "company": "Elasticsearch Servers (multiple)",
                "year": "2020-2023",
                "impact": "Billions of records exposed across hundreds of incidents",
                "details": "A recurring pattern of cloud storage left without access blocks, discovered by security researchers and attackers alike.",
            },
        ],
        "fix_code": '''resource "aws_s3_bucket_public_access_block" "BUCKET_NAME" {
  bucket = aws_s3_bucket.BUCKET_NAME.id

  # These four settings form a complete public access block:
  block_public_acls       = true   # Reject PUT requests with public ACLs
  block_public_policy     = true   # Reject bucket policies that grant public access
  ignore_public_acls      = true   # Ignore all public ACLs on the bucket
  restrict_public_buckets = true   # Restrict public access to the bucket
}''',
        "cis_benchmark": "CIS AWS Foundations Benchmark v3.0 — Rule 2.1.4: Ensure S3 bucket Public Access Block is enabled",
        "why_it_matters": (
            "The public access block is AWS's recommended defense-in-depth measure. "
            "It acts as an account-level or bucket-level override that prevents accidental "
            "public exposure regardless of individual policies."
        ),
    },

    "FT-SG-001": {
        "title": "Security Group Open to the World (0.0.0.0/0)",
        "attack_scenario": (
            "Your security group allows inbound traffic from ANY IP address on earth. "
            "Attackers run automated scanners (Shodan, Masscan, ZMap) that sweep the entire "
            "IPv4 space in under an hour. Your open port will be found within minutes of "
            "being exposed. From there, they attempt brute force logins, exploit known "
            "vulnerabilities, or use the open port as a pivot point into your network."
        ),
        "real_breaches": [
            {
                "company": "MongoDB Instances (mass attack)",
                "year": "2017",
                "impact": "28,000 databases wiped and held for ransom",
                "details": "Attackers scanned for MongoDB instances with open security groups, deleted all data, and left ransom notes demanding Bitcoin.",
            },
            {
                "company": "Tesla",
                "year": "2018",
                "impact": "Kubernetes console exposed, used for cryptomining",
                "details": "An unsecured Kubernetes dashboard accessible from 0.0.0.0/0 allowed attackers to deploy cryptominers on Tesla's AWS infrastructure.",
            },
        ],
        "fix_code": '''# INSTEAD of 0.0.0.0/0, restrict to specific IPs:
resource "aws_security_group" "web" {
  name   = "web-sg"
  vpc_id = aws_vpc.main.id

  ingress {
    description = "HTTPS from load balancer only"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    # Only allow from your load balancer's security group:
    security_groups = [aws_security_group.alb.id]
  }

  # If you MUST allow public access (web server behind ALB):
  # Only open port 443 (HTTPS), NEVER 22 (SSH) or 3389 (RDP)
  
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]  # Outbound is usually safe to open
  }

  tags = {
    Name = "web-sg"
  }
}''',
        "cis_benchmark": "CIS AWS Foundations Benchmark v3.0 — Rule 5.2: Ensure no security groups allow ingress from 0.0.0.0/0",
        "why_it_matters": (
            "Shodan.io indexes every public IP with open ports. Within minutes of opening "
            "a port to 0.0.0.0/0, automated scanners will find it. This is the #1 entry "
            "point for cloud infrastructure attacks."
        ),
    },

    "FT-SG-002": {
        "title": "SSH (Port 22) Open to the Internet",
        "attack_scenario": (
            "SSH on port 22 open to the internet is one of the most attacked configurations "
            "in cloud infrastructure. Attackers run continuous brute-force attacks against "
            "every public IP with port 22 open. They try common usernames (root, admin, ubuntu, "
            "ec2-user) with password lists containing millions of entries. If your key is weak "
            "or password auth is enabled, they're in. Even with strong keys, you're exposing "
            "your attack surface unnecessarily."
        ),
        "real_breaches": [
            {
                "company": "Alibaba Cloud Instances",
                "year": "2020",
                "impact": "Thousands of servers compromised for cryptomining",
                "details": "A botnet called 'Watchdog' exploited open SSH ports to install cryptominers across cloud instances worldwide.",
            },
        ],
        "fix_code": '''# BEST: Use AWS SSM Session Manager instead of SSH entirely
# (no open ports needed, fully audited, IAM-controlled)

# If you MUST use SSH, restrict to your IP:
resource "aws_security_group_rule" "ssh" {
  type              = "ingress"
  from_port         = 22
  to_port           = 22
  protocol          = "tcp"
  # Your office IP only:
  cidr_blocks       = ["203.0.113.50/32"]
  security_group_id = aws_security_group.bastion.id
  description       = "SSH from office IP only"
}

# EVEN BETTER: Use a bastion host in a private subnet
# and connect via SSM or VPN only''',
        "cis_benchmark": "CIS AWS Foundations Benchmark v3.0 — Rule 5.2: Ensure no security groups allow ingress from 0.0.0.0/0 to port 22",
        "why_it_matters": (
            "A single server with SSH open to the internet receives an average of "
            "13,000 brute force login attempts per day. Use SSM Session Manager instead — "
            "it requires no open ports and provides full audit logging."
        ),
    },

    "FT-RDS-001": {
        "title": "Publicly Accessible Database",
        "attack_scenario": (
            "Your database is directly reachable from the internet. An attacker can connect "
            "to it from anywhere. They'll try default credentials (postgres/postgres, "
            "admin/admin, root with no password). They'll try known exploits for your database "
            "version. If they get in, they have DIRECT access to all your data — user records, "
            "payment info, everything. No need to hack your application first."
        ),
        "real_breaches": [
            {
                "company": "Microsoft (Power Apps)",
                "year": "2021",
                "impact": "38 million records exposed from 47 organizations",
                "details": "Publicly accessible databases behind Power Apps portals exposed data from American Airlines, Ford, the state of Indiana, and others.",
            },
            {
                "company": "Facebook",
                "year": "2019",
                "impact": "540 million records found on public databases",
                "details": "Third-party apps stored Facebook user data in publicly accessible databases, exposing account names, IDs, and activity.",
            },
        ],
        "fix_code": '''resource "aws_db_instance" "main" {
  # ...existing config...

  # CRITICAL: Never make a production database public
  publicly_accessible = false

  # Place in private subnet:
  db_subnet_group_name = aws_db_subnet_group.private.name

  # Encrypt storage:
  storage_encrypted = true
  kms_key_id        = aws_kms_key.rds.arn

  # Enable backups:
  backup_retention_period = 14
  
  # Enable deletion protection:
  deletion_protection = true

  # Require SSL connections:
  parameter_group_name = aws_db_parameter_group.require_ssl.name
}

# Put in private subnets only:
resource "aws_db_subnet_group" "private" {
  name       = "private-db-subnets"
  subnet_ids = aws_subnet.private[*].id
}''',
        "cis_benchmark": "CIS AWS Foundations Benchmark v3.0 — Rule 2.3.1: Ensure RDS instances are not publicly accessible",
        "why_it_matters": (
            "A publicly accessible database is one vulnerability away from a complete "
            "data breach. Always place databases in private subnets with no internet access."
        ),
    },

    "FT-IAM-001": {
        "title": "IAM Policy with Wildcard Permissions (Action: *, Resource: *)",
        "attack_scenario": (
            "This IAM policy grants FULL access to EVERYTHING in your AWS account. "
            "If any service or user with this policy is compromised, the attacker can: "
            "delete all your resources, access all your data, create new admin users, "
            "change billing settings, launch expensive resources for cryptomining, and "
            "cover their tracks by deleting CloudTrail logs. This is equivalent to giving "
            "everyone the root account password."
        ),
        "real_breaches": [
            {
                "company": "Uber",
                "year": "2016",
                "impact": "57 million user records stolen",
                "details": "Attackers found AWS credentials with broad permissions in a GitHub repo. The overly permissive IAM policies let them access S3 buckets with rider and driver data.",
            },
            {
                "company": "SolarWinds (supply chain)",
                "year": "2020",
                "impact": "18,000 organizations compromised including US government",
                "details": "Compromised credentials with broad cloud permissions allowed attackers to move laterally through government and enterprise cloud environments.",
            },
        ],
        "fix_code": '''# NEVER do this:
#   "Action": "*",
#   "Resource": "*"

# INSTEAD, scope to exactly what's needed:
resource "aws_iam_policy" "app_policy" {
  name = "app-limited-policy"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "s3:GetObject",       # Only read from S3
          "s3:PutObject",       # Only write to S3
        ]
        Resource = [
          "arn:aws:s3:::my-app-bucket/*"  # Only this specific bucket
        ]
      },
      {
        Effect = "Allow"
        Action = [
          "logs:CreateLogGroup",
          "logs:CreateLogStream",
          "logs:PutLogEvents",
        ]
        Resource = "arn:aws:logs:*:*:*"  # Logging is fine to allow broadly
      }
    ]
  })
}''',
        "cis_benchmark": "CIS AWS Foundations Benchmark v3.0 — Rule 1.16: Ensure IAM policies are attached only to groups or roles (with least privilege)",
        "why_it_matters": (
            "IAM misconfigurations are the #1 cause of cloud security breaches. "
            "Every AWS resource should have a scoped policy with only the permissions "
            "it needs. Use the IAM Access Analyzer to find unused permissions."
        ),
    },

    "FT-SEC-001": {
        "title": "Hardcoded Secrets in Terraform Code",
        "attack_scenario": (
            "Your Terraform code contains a plaintext password, API key, or secret. "
            "When this code is pushed to Git, the secret is permanently in the commit "
            "history — even if you delete it later. Anyone with repo access (current and "
            "future employees, contractors, open-source contributors) can find it. Tools "
            "like TruffleHog, GitLeaks, and GitHub's own secret scanning constantly scan "
            "repos for exposed credentials."
        ),
        "real_breaches": [
            {
                "company": "Uber",
                "year": "2016",
                "impact": "AWS credentials in GitHub repo led to 57M record breach",
                "details": "Developers committed AWS access keys to a private GitHub repository. Attackers gained access and used the keys to exfiltrate data.",
            },
            {
                "company": "Samsung",
                "year": "2022",
                "impact": "Secret keys exposed in public GitLab repos",
                "details": "Researchers found Samsung employees had committed AWS keys, GitHub tokens, and internal credentials to public repositories.",
            },
        ],
        "fix_code": '''# NEVER hardcode secrets:
#   password = "my_secret_password"

# OPTION 1: Use AWS Secrets Manager
data "aws_secretsmanager_secret_version" "db_password" {
  secret_id = "prod/database/password"
}

resource "aws_db_instance" "main" {
  password = data.aws_secretsmanager_secret_version.db_password.secret_string
}

# OPTION 2: Use SSM Parameter Store
data "aws_ssm_parameter" "db_password" {
  name            = "/prod/database/password"
  with_decryption = true
}

# OPTION 3: Use environment variables
variable "db_password" {
  description = "Database password"
  type        = string
  sensitive   = true  # Marks as sensitive in plan output
}
# Then set via: TF_VAR_db_password=xxx terraform apply''',
        "cis_benchmark": "CIS AWS Foundations Benchmark v3.0 — Multiple rules on credential management",
        "why_it_matters": (
            "GitHub reports that over 100 million secrets were pushed to public repos in "
            "2024 alone. Once a secret is in Git history, it's effectively permanent. "
            "Always use a secrets manager."
        ),
    },

    "FT-RDS-002": {
        "title": "Database Without Encryption at Rest",
        "attack_scenario": (
            "Your database stores data on disk without encryption. If an attacker gains "
            "access to the underlying storage (through an AWS vulnerability, a snapshot "
            "that's shared, or a backup that's exposed), they can read all your data in "
            "plaintext. Encryption at rest prevents this — even if they get the raw storage, "
            "they can't read it without the KMS key."
        ),
        "real_breaches": [
            {
                "company": "Multiple Healthcare Providers",
                "year": "2019-2023",
                "impact": "HIPAA violations and millions in fines",
                "details": "Unencrypted databases containing patient health records resulted in regulatory fines when breaches occurred.",
            },
        ],
        "fix_code": '''resource "aws_db_instance" "main" {
  # Enable encryption at rest:
  storage_encrypted = true
  
  # Use a customer-managed KMS key (recommended for compliance):
  kms_key_id = aws_kms_key.rds.arn
}

# Create a dedicated KMS key for your database:
resource "aws_kms_key" "rds" {
  description             = "KMS key for RDS encryption"
  deletion_window_in_days = 30
  enable_key_rotation     = true  # Auto-rotate annually

  tags = {
    Purpose = "RDS encryption"
  }
}''',
        "cis_benchmark": "CIS AWS Foundations Benchmark v3.0 — Rule 2.3.1: Ensure RDS encryption is enabled",
        "why_it_matters": (
            "Encryption at rest is a baseline requirement for every compliance framework "
            "(SOC2, HIPAA, PCI-DSS, GDPR). It's also free in AWS — there's no reason not to enable it."
        ),
    },

    "FT-EKS-001": {
        "title": "EKS Cluster API Endpoint Public",
        "attack_scenario": (
            "Your Kubernetes API server is accessible from the internet. This means anyone "
            "can attempt to authenticate to your cluster. If there's a Kubernetes vulnerability, "
            "a misconfigured RBAC role, or a leaked kubeconfig file, attackers can access your "
            "cluster from anywhere in the world and deploy malicious workloads, steal secrets, "
            "or pivot to other AWS resources."
        ),
        "real_breaches": [
            {
                "company": "Tesla",
                "year": "2018",
                "impact": "Kubernetes console exposed, cryptomining deployed",
                "details": "An unsecured Kubernetes dashboard was accessible from the internet, allowing attackers to deploy cryptominers on Tesla's cloud.",
            },
        ],
        "fix_code": '''resource "aws_eks_cluster" "main" {
  name     = "production"
  role_arn = aws_iam_role.eks.arn

  vpc_config {
    # Make the API endpoint private:
    endpoint_private_access = true
    endpoint_public_access  = false

    # If you MUST have public access, restrict to your IPs:
    # endpoint_public_access  = true
    # public_access_cidrs     = ["203.0.113.0/24"]

    subnet_ids = aws_subnet.private[*].id
    security_group_ids = [aws_security_group.eks.id]
  }
}''',
        "cis_benchmark": "CIS Amazon EKS Benchmark v1.4 — Rule 5.4.1: Restrict cluster API endpoint to private",
        "why_it_matters": (
            "A public Kubernetes API is a direct path into your cluster. Use a VPN "
            "or private endpoint to access it. Never expose it to the internet."
        ),
    },
}


def get_scenario(rule_id: str) -> Optional[Dict]:
    """Get the attack scenario for a given rule ID."""
    return ATTACK_SCENARIOS.get(rule_id)


def get_all_scenarios() -> Dict:
    """Get all available attack scenarios."""
    return ATTACK_SCENARIOS


def format_breach(breach: Dict) -> str:
    """Format a breach reference for display."""
    return f"{breach['company']} ({breach['year']}) — {breach['impact']}"
