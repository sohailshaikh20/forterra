"""
AI Engine — The brain of Forterra.

HOW THIS WORKS:
- This module talks to the Anthropic (Claude) API
- It sends carefully crafted prompts that tell Claude to act as a security architect
- Claude returns structured JSON with Terraform code + security metadata
- We parse that JSON and return it to the CLI commands

YOU CAN MODIFY:
- The prompts (SYSTEM_PROMPT, etc.) to change what security rules Forterra enforces
- The model (currently claude-sonnet-4-20250514) — you can upgrade when new models come out
- The compliance frameworks and hardening rules
"""

import os
import json
from pathlib import Path

from dotenv import load_dotenv

# Load .env file if it exists (so users can put their API key there)
load_dotenv()


# ============================================================
# SYSTEM PROMPT — This is the "personality" of Forterra's AI
# Modify this to change what security rules Forterra enforces
# ============================================================
SYSTEM_PROMPT = """You are Forterra, an expert AI Security Architect specializing in Terraform and cloud infrastructure security.

Your job is to generate SECURE, production-grade Terraform code that follows these principles:

SECURITY RULES (always enforce):
1. ENCRYPTION: Enable encryption at rest (AES-256) and in transit (TLS 1.2+) for ALL resources that support it
2. NETWORK: Use private subnets by default. Never expose resources to 0.0.0.0/0 unless explicitly requested
3. IAM: Follow least-privilege principle. No wildcard (*) permissions. Scoped roles per service
4. STORAGE: Block all public access on S3 buckets, storage accounts, etc.
5. DATABASE: No public accessibility. Enable automated backups. Enforce SSL connections
6. LOGGING: Enable CloudTrail, VPC Flow Logs, access logging on load balancers
7. SECURITY GROUPS: Minimal port openings. No unrestricted ingress
8. SECRETS: Never hardcode secrets. Use AWS Secrets Manager, Azure Key Vault, or GCP Secret Manager
9. VERSIONING: Pin provider and module versions
10. TAGGING: Add security-relevant tags (ManagedBy, Environment, Compliance)

CIS BENCHMARK RULES:
- CIS AWS Foundations Benchmark v3.0
- CIS Azure Foundations Benchmark v2.1
- CIS GCP Foundations Benchmark v2.0

TERRAFORM BEST PRACTICES:
- Modular structure (separate modules for vpc, compute, database, iam, etc.)
- Use variables with descriptions and validation
- Use outputs for important values
- Use locals for computed values
- Add comments explaining security decisions
- Use data sources where appropriate

OUTPUT FORMAT:
Always respond with valid JSON only. No markdown, no backticks, no explanation outside the JSON.
"""

GENERATE_PROMPT = """Generate secure Terraform for this architecture:

DESCRIPTION: {prompt}
PROVIDER: {provider}
COMPLIANCE: {compliance}

Respond with ONLY this JSON structure:
{{
  "success": true,
  "security_score": <number 0-100>,
  "score_grade": "<A+/A/B/C/D/F>",
  "resources_count": <number of resources>,
  "modules": ["<module names>"],
  "hardening_applied": ["<list of specific security measures applied>"],
  "files": {{
    "main.tf": "<terraform code>",
    "variables.tf": "<terraform code>",
    "outputs.tf": "<terraform code>",
    "providers.tf": "<terraform code>"
  }}
}}

Make the Terraform code production-ready with comments explaining every security decision."""

FIX_PROMPT = """Fix this Terraform security issue:

SEVERITY: {severity}
RESOURCE: {resource}
FILE: {file}
ISSUE: {message}
CURRENT CODE: {code}

Respond with ONLY this JSON:
{{
  "success": true,
  "description": "<what was fixed and why>",
  "fixed_code": "<the corrected terraform code>"
}}"""


class AIEngine:
    """
    The AI Engine handles all communication with Claude API.

    Usage:
        ai = AIEngine()
        result = ai.generate_infrastructure("three tier app on AWS")
    """

    def __init__(self):
        # Look for API key in these places (in order):
        # 1. FORTERRA_API_KEY environment variable
        # 2. ANTHROPIC_API_KEY environment variable
        # 3. .env file in current directory
        self.api_key = os.getenv("FORTERRA_API_KEY") or os.getenv("ANTHROPIC_API_KEY")

    def has_api_key(self) -> bool:
        """Check if an API key is available."""
        return bool(self.api_key)

    def generate_infrastructure(self, prompt: str, provider: str = "aws", compliance: list = None) -> dict:
        """
        Generate secure Terraform from a plain English description.

        Args:
            prompt: Architecture description (e.g., "VPC with EKS and RDS on AWS")
            provider: Cloud provider (aws, azure, gcp)
            compliance: List of compliance frameworks (cis, soc2, hipaa, pci)

        Returns:
            Dict with security_score, files, hardening_applied, etc.
        """
        if not self.has_api_key():
            return {"success": False, "error": "No API key configured"}

        compliance_str = ", ".join(compliance) if compliance else "CIS"

        user_prompt = GENERATE_PROMPT.format(
            prompt=prompt,
            provider=provider,
            compliance=compliance_str,
        )

        try:
            # Import anthropic here so the rest of the tool works even without the SDK
            import anthropic

            client = anthropic.Anthropic(api_key=self.api_key)

            message = client.messages.create(
                model="claude-sonnet-4-20250514",
                max_tokens=4096,
                system=SYSTEM_PROMPT,
                messages=[{"role": "user", "content": user_prompt}],
            )

            # Parse the response
            response_text = ""
            for block in message.content:
                if hasattr(block, "text"):
                    response_text += block.text

            # Clean and parse JSON
            response_text = response_text.strip()
            response_text = response_text.replace("```json", "").replace("```", "").strip()
            result = json.loads(response_text)
            return result

        except json.JSONDecodeError as e:
            return {"success": False, "error": f"Failed to parse AI response: {e}"}
        except Exception as e:
            return {"success": False, "error": str(e)}

    def generate_fix(self, issue: dict) -> dict:
        """
        Generate an AI-powered fix for a security issue.

        Args:
            issue: Dict with severity, resource, message, file, code

        Returns:
            Dict with success, description, fixed_code
        """
        if not self.has_api_key():
            return {"success": False, "error": "No API key configured"}

        user_prompt = FIX_PROMPT.format(
            severity=issue.get("severity", "UNKNOWN"),
            resource=issue.get("resource", "unknown"),
            file=issue.get("file", "unknown"),
            message=issue.get("message", ""),
            code=issue.get("code", "# No code available"),
        )

        try:
            import anthropic

            client = anthropic.Anthropic(api_key=self.api_key)

            message = client.messages.create(
                model="claude-sonnet-4-20250514",
                max_tokens=2048,
                system=SYSTEM_PROMPT,
                messages=[{"role": "user", "content": user_prompt}],
            )

            response_text = ""
            for block in message.content:
                if hasattr(block, "text"):
                    response_text += block.text

            response_text = response_text.strip().replace("```json", "").replace("```", "").strip()
            return json.loads(response_text)

        except Exception as e:
            return {"success": False, "error": str(e)}
