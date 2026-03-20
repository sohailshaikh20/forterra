"""
Plan Analyzer — The core of Forterra.

HOW THIS WORKS:
1. User runs: terraform plan -out=tfplan && terraform show -json tfplan > plan.json
2. Or pipes it: terraform plan -json | forterra analyze
3. We parse the JSON plan output from Terraform
4. We check every resource change against security rules
5. We classify changes as DANGEROUS / WORTH REVIEWING / SAFE
6. AI provides plain-English explanations of what each change means

The key insight: Checkov/Trivy scan your .tf FILES (static code).
Forterra scans your PLAN (what's actually about to happen).
This catches things static scanners miss — like a destroy-and-recreate
that will cause downtime, or a security group change that opens a port.

YOU CAN MODIFY:
- Add rules to PLAN_RULES for new dangerous patterns
- Change risk scoring weights
- Modify the AI prompt for different explanation styles
"""

import json
import sys
import re
from pathlib import Path
from typing import Dict, List, Tuple, Optional


# ============================================================
# RISK CLASSIFICATION RULES
# These check the PLAN output (what Terraform is about to do)
# NOT the static .tf files
# ============================================================

# Actions that Terraform can take on resources
ACTION_RISK = {
    "delete": {"base_risk": 40, "label": "DESTROY"},
    "create": {"base_risk": 5, "label": "CREATE"},
    "update": {"base_risk": 10, "label": "UPDATE"},
    "replace": {"base_risk": 50, "label": "DESTROY & RECREATE"},  # Most dangerous
    "read": {"base_risk": 0, "label": "READ"},
    "no-op": {"base_risk": 0, "label": "NO CHANGE"},
}

# Resource types that are high-risk when destroyed/replaced
HIGH_RISK_RESOURCES = {
    "aws_db_instance": {
        "risk_multiplier": 3,
        "reason": "Database destruction can cause permanent data loss",
        "downtime": True,
    },
    "aws_rds_cluster": {
        "risk_multiplier": 3,
        "reason": "RDS cluster changes can cause extended downtime",
        "downtime": True,
    },
    "aws_s3_bucket": {
        "risk_multiplier": 2.5,
        "reason": "S3 bucket deletion removes all objects permanently",
        "downtime": False,
    },
    "aws_vpc": {
        "risk_multiplier": 3,
        "reason": "VPC changes can isolate all resources in the network",
        "downtime": True,
    },
    "aws_subnet": {
        "risk_multiplier": 2,
        "reason": "Subnet changes can disrupt network connectivity",
        "downtime": True,
    },
    "aws_iam_role": {
        "risk_multiplier": 2,
        "reason": "IAM role changes can break service permissions immediately",
        "downtime": False,
    },
    "aws_iam_policy": {
        "risk_multiplier": 2,
        "reason": "Policy changes affect all attached roles/users instantly",
        "downtime": False,
    },
    "aws_eks_cluster": {
        "risk_multiplier": 3,
        "reason": "EKS cluster replacement causes major downtime for all workloads",
        "downtime": True,
    },
    "aws_elasticache_cluster": {
        "risk_multiplier": 2,
        "reason": "Cache cluster replacement causes temporary data loss and downtime",
        "downtime": True,
    },
    "aws_lb": {
        "risk_multiplier": 2,
        "reason": "Load balancer changes can drop all active connections",
        "downtime": True,
    },
    "aws_route53_record": {
        "risk_multiplier": 1.5,
        "reason": "DNS changes can make services unreachable (with TTL delay)",
        "downtime": True,
    },
    "aws_security_group": {
        "risk_multiplier": 2,
        "reason": "Security group changes affect network access immediately",
        "downtime": False,
    },
    "azurerm_sql_database": {
        "risk_multiplier": 3,
        "reason": "Database destruction can cause permanent data loss",
        "downtime": True,
    },
    "azurerm_kubernetes_cluster": {
        "risk_multiplier": 3,
        "reason": "AKS cluster replacement causes major downtime",
        "downtime": True,
    },
    "google_sql_database_instance": {
        "risk_multiplier": 3,
        "reason": "Cloud SQL replacement causes downtime and potential data loss",
        "downtime": True,
    },
    "google_container_cluster": {
        "risk_multiplier": 3,
        "reason": "GKE cluster replacement causes major downtime",
        "downtime": True,
    },
}

# Specific attribute changes that are security-sensitive
DANGEROUS_ATTRIBUTE_CHANGES = [
    {
        "resource_pattern": r"aws_security_group",
        "attribute": "ingress",
        "check": lambda before, after: _cidr_opened_wider(before, after),
        "message": "Security group ingress rule is being opened wider",
        "severity": "HIGH",
    },
    {
        "resource_pattern": r"aws_s3_bucket",
        "attribute": "acl",
        "check": lambda before, after: after in ("public-read", "public-read-write"),
        "message": "S3 bucket ACL is being set to public",
        "severity": "CRITICAL",
    },
    {
        "resource_pattern": r"aws_db_instance",
        "attribute": "publicly_accessible",
        "check": lambda before, after: after is True,
        "message": "Database is being made publicly accessible",
        "severity": "CRITICAL",
    },
    {
        "resource_pattern": r"aws_db_instance",
        "attribute": "storage_encrypted",
        "check": lambda before, after: after is False and before is True,
        "message": "Database encryption is being DISABLED",
        "severity": "CRITICAL",
    },
    {
        "resource_pattern": r"aws_db_instance",
        "attribute": "backup_retention_period",
        "check": lambda before, after: _is_number(after) and int(after) == 0,
        "message": "Database backups are being disabled",
        "severity": "HIGH",
    },
    {
        "resource_pattern": r"aws_instance",
        "attribute": "associate_public_ip_address",
        "check": lambda before, after: after is True and before is not True,
        "message": "EC2 instance is being given a public IP",
        "severity": "MEDIUM",
    },
    {
        "resource_pattern": r"aws_eks_cluster",
        "attribute": "endpoint_public_access",
        "check": lambda before, after: after is True,
        "message": "EKS API endpoint is being made public",
        "severity": "HIGH",
    },
    {
        "resource_pattern": r"aws_iam",
        "attribute": "policy",
        "check": lambda before, after: _policy_has_wildcard(after),
        "message": "IAM policy now includes wildcard (*) permissions",
        "severity": "CRITICAL",
    },
]


def _cidr_opened_wider(before, after):
    """Check if a CIDR block was opened to a wider range."""
    if isinstance(after, str) and "0.0.0.0/0" in after:
        return True
    if isinstance(after, list) and any("0.0.0.0/0" in str(item) for item in after):
        return True
    return False


def _policy_has_wildcard(policy):
    """Check if an IAM policy contains wildcard actions or resources."""
    if isinstance(policy, str):
        return '"*"' in policy and ('"Action"' in policy or '"Resource"' in policy)
    return False


def _is_number(val):
    """Check if a value can be converted to int."""
    try:
        int(val)
        return True
    except (TypeError, ValueError):
        return False


class PlanAnalyzer:
    """
    Analyzes Terraform plan JSON output for security risks.

    Usage:
        analyzer = PlanAnalyzer()
        result = analyzer.analyze_plan("plan.json")
        # or
        result = analyzer.analyze_plan_data(json_dict)
    """

    def load_plan(self, path: str) -> Optional[dict]:
        """Load a Terraform plan JSON file."""
        try:
            plan_path = Path(path)
            if not plan_path.exists():
                return None
            with open(plan_path) as f:
                return json.load(f)
        except json.JSONDecodeError:
            return None

    def load_plan_from_stdin(self) -> Optional[dict]:
        """Load plan JSON from stdin (for piping)."""
        try:
            data = sys.stdin.read()
            return json.loads(data)
        except (json.JSONDecodeError, Exception):
            return None

    def analyze_plan(self, plan_path: str) -> dict:
        """Analyze a plan from a file path."""
        plan_data = self.load_plan(plan_path)
        if not plan_data:
            return {"success": False, "error": f"Could not load plan from {plan_path}"}
        return self.analyze_plan_data(plan_data)

    def analyze_plan_data(self, plan_data: dict) -> dict:
        """
        Analyze a Terraform plan and return a structured risk assessment.

        Returns:
            {
                "success": True,
                "risk_score": 0-100,
                "risk_level": "LOW" | "MEDIUM" | "HIGH" | "CRITICAL",
                "summary": { "total": N, "create": N, "update": N, "delete": N, "replace": N },
                "dangerous_changes": [...],
                "review_changes": [...],
                "safe_changes": [...],
                "security_issues": [...],
            }
        """
        # Extract resource changes from plan
        resource_changes = self._extract_resource_changes(plan_data)

        if not resource_changes:
            return {
                "success": True,
                "risk_score": 100,
                "risk_level": "NONE",
                "summary": {"total": 0, "create": 0, "update": 0, "delete": 0, "replace": 0},
                "dangerous_changes": [],
                "review_changes": [],
                "safe_changes": [],
                "security_issues": [],
            }

        # Classify each change
        dangerous = []
        review = []
        safe = []
        security_issues = []
        total_risk = 0

        summary = {"total": len(resource_changes), "create": 0, "update": 0, "delete": 0, "replace": 0, "no_change": 0}

        for change in resource_changes:
            risk_score, classification, reasons = self._assess_change(change)
            change["risk_score"] = risk_score
            change["reasons"] = reasons
            total_risk += risk_score

            # Count by action type
            action = change.get("action", "no-op")
            if action == "delete":
                summary["delete"] += 1
            elif action == "create":
                summary["create"] += 1
            elif action in ("update", "update-in-place"):
                summary["update"] += 1
            elif action in ("replace", "delete-create", "create-delete"):
                summary["replace"] += 1
            else:
                summary["no_change"] += 1

            # Classify
            if classification == "dangerous":
                dangerous.append(change)
            elif classification == "review":
                review.append(change)
            else:
                safe.append(change)

            # Check for specific security attribute changes
            sec_issues = self._check_security_attributes(change)
            security_issues.extend(sec_issues)

        # Calculate overall risk score (0 = very risky, 100 = safe)
        max_possible_risk = len(resource_changes) * 50  # normalize
        normalized_risk = min(total_risk / max(max_possible_risk, 1) * 100, 100)
        safety_score = max(0, int(100 - normalized_risk))

        if safety_score >= 90:
            risk_level = "LOW"
        elif safety_score >= 70:
            risk_level = "MEDIUM"
        elif safety_score >= 40:
            risk_level = "HIGH"
        else:
            risk_level = "CRITICAL"

        # Sort dangerous by risk score descending
        dangerous.sort(key=lambda x: x["risk_score"], reverse=True)
        review.sort(key=lambda x: x["risk_score"], reverse=True)

        return {
            "success": True,
            "risk_score": safety_score,
            "risk_level": risk_level,
            "summary": summary,
            "dangerous_changes": dangerous,
            "review_changes": review,
            "safe_changes": safe,
            "security_issues": security_issues,
        }

    def _extract_resource_changes(self, plan_data: dict) -> list:
        """Extract resource changes from Terraform plan JSON."""
        changes = []

        # Terraform plan JSON has resource_changes at the top level
        resource_changes = plan_data.get("resource_changes", [])

        for rc in resource_changes:
            change_info = rc.get("change", {})
            actions = change_info.get("actions", ["no-op"])

            # Determine the primary action
            if "delete" in actions and "create" in actions:
                action = "replace"
            elif "delete" in actions:
                action = "delete"
            elif "create" in actions:
                action = "create"
            elif "update" in actions:
                action = "update"
            else:
                action = "no-op"

            if action == "no-op":
                continue  # Skip unchanged resources

            resource_type = rc.get("type", "unknown")
            resource_name = rc.get("name", "unknown")
            address = rc.get("address", f"{resource_type}.{resource_name}")

            changes.append({
                "address": address,
                "resource_type": resource_type,
                "resource_name": resource_name,
                "action": action,
                "before": change_info.get("before", {}),
                "after": change_info.get("after", {}),
                "before_sensitive": change_info.get("before_sensitive", {}),
                "after_sensitive": change_info.get("after_sensitive", {}),
            })

        return changes

    def _assess_change(self, change: dict) -> Tuple[int, str, List[str]]:
        """
        Assess the risk of a single resource change.

        Returns: (risk_score, classification, reasons)
            classification: "dangerous" | "review" | "safe"
        """
        action = change.get("action", "no-op")
        resource_type = change.get("resource_type", "")
        reasons = []

        # Base risk from action type
        action_info = ACTION_RISK.get(action, {"base_risk": 5, "label": action})
        risk = action_info["base_risk"]

        # Multiply risk for high-value resources
        if resource_type in HIGH_RISK_RESOURCES:
            resource_info = HIGH_RISK_RESOURCES[resource_type]
            risk *= resource_info["risk_multiplier"]
            reasons.append(resource_info["reason"])
            if resource_info.get("downtime") and action in ("delete", "replace"):
                reasons.append("⚠️  THIS WILL LIKELY CAUSE DOWNTIME")
                risk += 20

        # Extra risk for destructive actions on data stores
        if action in ("delete", "replace") and any(kw in resource_type for kw in ("db_", "s3_bucket", "rds_", "sql_", "elasticache")):
            reasons.append("Data-bearing resource is being destroyed")
            risk += 15

        # Check if security-sensitive attributes are changing
        if action == "update":
            sec_reasons = self._check_attribute_changes(change)
            reasons.extend(sec_reasons)
            risk += len(sec_reasons) * 15

        # Classify based on risk score
        if risk >= 40:
            classification = "dangerous"
        elif risk >= 15:
            classification = "review"
        else:
            classification = "safe"

        return risk, classification, reasons

    def _check_attribute_changes(self, change: dict) -> List[str]:
        """Check for specific dangerous attribute changes."""
        reasons = []
        resource_type = change.get("resource_type", "")
        before = change.get("before", {}) or {}
        after = change.get("after", {}) or {}

        for rule in DANGEROUS_ATTRIBUTE_CHANGES:
            if not re.search(rule["resource_pattern"], resource_type):
                continue

            attr = rule["attribute"]
            before_val = before.get(attr)
            after_val = after.get(attr)

            # Only check if the attribute exists and is changing
            if after_val is not None and before_val != after_val:
                try:
                    if rule["check"](before_val, after_val):
                        reasons.append(f"🔒 SECURITY: {rule['message']}")
                except Exception:
                    pass

        return reasons

    def _check_security_attributes(self, change: dict) -> list:
        """Check for security-specific issues in a change."""
        issues = []
        resource_type = change.get("resource_type", "")
        after = change.get("after", {}) or {}
        address = change.get("address", "unknown")

        for rule in DANGEROUS_ATTRIBUTE_CHANGES:
            if not re.search(rule["resource_pattern"], resource_type):
                continue

            attr = rule["attribute"]
            after_val = after.get(attr)
            before_val = (change.get("before") or {}).get(attr)

            if after_val is not None and before_val != after_val:
                try:
                    if rule["check"](before_val, after_val):
                        issues.append({
                            "resource": address,
                            "severity": rule["severity"],
                            "message": rule["message"],
                            "attribute": attr,
                            "before": str(before_val)[:100] if before_val else "null",
                            "after": str(after_val)[:100] if after_val else "null",
                        })
                except Exception:
                    pass

        return issues

    def format_change_summary(self, change: dict) -> str:
        """Format a single change for display."""
        action_info = ACTION_RISK.get(change.get("action", "no-op"), {"label": "UNKNOWN"})
        return f"{action_info['label']}: {change['address']}"
