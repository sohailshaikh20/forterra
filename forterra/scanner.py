"""
Scanner — Scans existing Terraform files for security issues.

HOW THIS WORKS:
- This module reads .tf files and checks them against built-in security rules
- It does NOT need an API key — it works completely offline
- Rules are defined in the SECURITY_RULES list below
- Each rule has a regex pattern that matches insecure configurations

YOU CAN MODIFY:
- Add new rules to SECURITY_RULES to catch more issues
- Change severity levels
- Add fix hints for each rule
- Add support for new resource types

This is the "free" part of Forterra — scanning is always free.
The AI-powered fixing/generation is what needs the API key.
"""

import re
from pathlib import Path
from typing import List, Dict


# ============================================================
# SECURITY RULES
# Each rule checks for a specific misconfiguration.
# These run locally — no API needed.
#
# To add a new rule, copy an existing one and modify:
#   - id: Unique identifier
#   - severity: CRITICAL, HIGH, MEDIUM, or LOW
#   - resource_pattern: Regex to match the resource type
#   - vuln_pattern: Regex that matches the INSECURE configuration
#   - message: Human-readable description
#   - fix_hint: Suggestion for how to fix it
# ============================================================
SECURITY_RULES = [
    # --- S3 / Storage ---
    {
        "id": "FT-S3-001",
        "severity": "CRITICAL",
        "resource_pattern": r'resource\s+"aws_s3_bucket"',
        "vuln_pattern": r'acl\s*=\s*"public-read"',
        "message": "S3 bucket has public-read ACL — data is exposed to the internet",
        "fix_hint": "Remove the ACL or set to 'private'. Add aws_s3_bucket_public_access_block.",
    },
    {
        "id": "FT-S3-002",
        "severity": "HIGH",
        "resource_pattern": r'resource\s+"aws_s3_bucket"',
        "check_missing": r'aws_s3_bucket_public_access_block',
        "message": "S3 bucket missing public access block — should explicitly block public access",
        "fix_hint": "Add an aws_s3_bucket_public_access_block resource with all settings set to true.",
    },
    {
        "id": "FT-S3-003",
        "severity": "HIGH",
        "resource_pattern": r'resource\s+"aws_s3_bucket"',
        "check_missing": r'aws_s3_bucket_server_side_encryption_configuration',
        "message": "S3 bucket missing server-side encryption configuration",
        "fix_hint": "Add aws_s3_bucket_server_side_encryption_configuration with AES256 or aws:kms.",
    },

    # --- Security Groups ---
    {
        "id": "FT-SG-001",
        "severity": "CRITICAL",
        "resource_pattern": r'resource\s+"aws_security_group"',
        "vuln_pattern": r'cidr_blocks\s*=\s*\[\s*"0\.0\.0\.0/0"\s*\]',
        "message": "Security group allows unrestricted inbound access (0.0.0.0/0)",
        "fix_hint": "Restrict CIDR blocks to specific IP ranges or use a VPN.",
    },
    {
        "id": "FT-SG-002",
        "severity": "HIGH",
        "resource_pattern": r'resource\s+"aws_security_group_rule"',
        "vuln_pattern": r'from_port\s*=\s*22[\s\S]*?cidr_blocks\s*=\s*\[\s*"0\.0\.0\.0/0"\s*\]',
        "message": "SSH (port 22) is open to the entire internet",
        "fix_hint": "Restrict SSH access to specific IP ranges or use SSM Session Manager instead.",
    },
    {
        "id": "FT-SG-003",
        "severity": "HIGH",
        "resource_pattern": r'resource\s+"aws_security_group_rule"',
        "vuln_pattern": r'from_port\s*=\s*3389[\s\S]*?cidr_blocks\s*=\s*\[\s*"0\.0\.0\.0/0"\s*\]',
        "message": "RDP (port 3389) is open to the entire internet",
        "fix_hint": "Restrict RDP access to specific IP ranges or use a bastion host.",
    },

    # --- RDS / Databases ---
    {
        "id": "FT-RDS-001",
        "severity": "CRITICAL",
        "resource_pattern": r'resource\s+"aws_db_instance"',
        "vuln_pattern": r'publicly_accessible\s*=\s*true',
        "message": "RDS instance is publicly accessible — database exposed to internet",
        "fix_hint": "Set publicly_accessible = false and access via VPN or private subnet.",
    },
    {
        "id": "FT-RDS-002",
        "severity": "HIGH",
        "resource_pattern": r'resource\s+"aws_db_instance"',
        "vuln_pattern": r'storage_encrypted\s*=\s*false',
        "message": "RDS instance does not have encryption at rest enabled",
        "fix_hint": "Set storage_encrypted = true.",
    },
    {
        "id": "FT-RDS-003",
        "severity": "MEDIUM",
        "resource_pattern": r'resource\s+"aws_db_instance"',
        "vuln_pattern": r'backup_retention_period\s*=\s*0',
        "message": "RDS automated backups are disabled",
        "fix_hint": "Set backup_retention_period to at least 7.",
    },

    # --- IAM ---
    {
        "id": "FT-IAM-001",
        "severity": "CRITICAL",
        "resource_pattern": r'resource\s+"aws_iam_policy"',
        "vuln_pattern": r'"Action"\s*:\s*"\*"[\s\S]*?"Resource"\s*:\s*"\*"',
        "message": "IAM policy grants full access (Action: *, Resource: *) — violates least privilege",
        "fix_hint": "Scope actions and resources to only what's needed.",
    },
    {
        "id": "FT-IAM-002",
        "severity": "HIGH",
        "resource_pattern": r'resource\s+"aws_iam_user_policy"',
        "vuln_pattern": r'"Effect"\s*:\s*"Allow"[\s\S]*?"Action"\s*:\s*"\*"',
        "message": "IAM user has wildcard permissions — should use roles instead of user policies",
        "fix_hint": "Use IAM roles with scoped policies instead of attaching policies to users.",
    },

    # --- EC2 ---
    {
        "id": "FT-EC2-001",
        "severity": "MEDIUM",
        "resource_pattern": r'resource\s+"aws_instance"',
        "vuln_pattern": r'associate_public_ip_address\s*=\s*true',
        "message": "EC2 instance has public IP — consider using a load balancer or NAT gateway",
        "fix_hint": "Set associate_public_ip_address = false. Use a load balancer for web traffic.",
    },

    # --- EKS ---
    {
        "id": "FT-EKS-001",
        "severity": "HIGH",
        "resource_pattern": r'resource\s+"aws_eks_cluster"',
        "vuln_pattern": r'endpoint_public_access\s*=\s*true',
        "message": "EKS cluster API endpoint is public — should be private",
        "fix_hint": "Set endpoint_public_access = false and endpoint_private_access = true.",
    },

    # --- Secrets in Code ---
    {
        "id": "FT-SEC-001",
        "severity": "CRITICAL",
        "resource_pattern": r'.*',
        "vuln_pattern": r'(?:password|secret_key|access_key|api_key|token)\s*=\s*"[^"]{8,}"',
        "message": "Possible hardcoded secret or credential in Terraform code",
        "fix_hint": "Use AWS Secrets Manager, SSM Parameter Store, or environment variables.",
    },

    # --- General ---
    {
        "id": "FT-GEN-001",
        "severity": "LOW",
        "resource_pattern": r'terraform\s*{',
        "check_missing": r'required_version',
        "message": "Terraform version not pinned — may break with future updates",
        "fix_hint": "Add required_version = \">= 1.5\" to your terraform block.",
    },
]


class Scanner:
    """
    Scans Terraform files for security misconfigurations.
    Works completely offline — no API key needed.
    """

    def find_terraform_files(self, path: str) -> List[Path]:
        """Find all .tf files in a directory."""
        root = Path(path)
        if root.is_file() and root.suffix == ".tf":
            return [root]
        return sorted(root.rglob("*.tf"))

    def scan_files(self, tf_files: List[Path]) -> List[Dict]:
        """
        Scan a list of Terraform files against all security rules.

        Returns a list of issues found.
        """
        issues = []

        # Read all file contents
        all_content = {}
        combined_content = ""
        for tf_file in tf_files:
            try:
                content = tf_file.read_text()
                all_content[str(tf_file)] = content
                combined_content += content + "\n"
            except Exception:
                continue

        # Check each file against each rule
        for filepath, content in all_content.items():
            for rule in SECURITY_RULES:
                # Check if the resource type exists in this file
                if not re.search(rule["resource_pattern"], content):
                    continue

                # Check for vulnerability pattern
                if "vuln_pattern" in rule:
                    matches = re.finditer(rule["vuln_pattern"], content)
                    for match in matches:
                        # Find the resource name
                        resource_name = self._find_resource_name(content, match.start())
                        issues.append({
                            "id": rule["id"],
                            "severity": rule["severity"],
                            "resource": resource_name,
                            "message": rule["message"],
                            "fix_hint": rule.get("fix_hint", ""),
                            "file": filepath,
                            "line": content[:match.start()].count("\n") + 1,
                            "code": match.group(0)[:200],
                        })

                # Check for missing configurations
                if "check_missing" in rule:
                    if not re.search(rule["check_missing"], combined_content):
                        resource_name = self._find_first_resource(content, rule["resource_pattern"])
                        if resource_name:
                            issues.append({
                                "id": rule["id"],
                                "severity": rule["severity"],
                                "resource": resource_name,
                                "message": rule["message"],
                                "fix_hint": rule.get("fix_hint", ""),
                                "file": filepath,
                                "line": 0,
                                "code": "",
                            })

        # Deduplicate
        seen = set()
        unique_issues = []
        for issue in issues:
            key = f"{issue['id']}:{issue['resource']}"
            if key not in seen:
                seen.add(key)
                unique_issues.append(issue)

        return unique_issues

    def count_resources(self, tf_files: List[Path]) -> int:
        """Count the total number of Terraform resources across all files."""
        count = 0
        for tf_file in tf_files:
            try:
                content = tf_file.read_text()
                count += len(re.findall(r'resource\s+"[^"]+"\s+"[^"]+"', content))
            except Exception:
                continue
        return count

    def _find_resource_name(self, content: str, position: int) -> str:
        """Find the resource name that contains the given position."""
        before = content[:position]
        matches = list(re.finditer(r'resource\s+"([^"]+)"\s+"([^"]+)"', before))
        if matches:
            last = matches[-1]
            return f"{last.group(1)}.{last.group(2)}"
        return "unknown"

    def _find_first_resource(self, content: str, pattern: str) -> str:
        """Find the first resource matching a pattern."""
        match = re.search(pattern + r'\s+"([^"]+)"', content)
        if match:
            # Extract resource type from the pattern
            type_match = re.search(r'"(aws_\w+)"', content[match.start():match.end() + 50])
            name_match = re.search(r'resource\s+"([^"]+)"\s+"([^"]+)"', content[match.start():match.end() + 100])
            if name_match:
                return f"{name_match.group(1)}.{name_match.group(2)}"
        return None
