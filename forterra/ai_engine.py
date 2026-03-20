"""AI engine — connects to Claude API for Terraform generation and remediation."""

import os
import json
from dotenv import load_dotenv

load_dotenv()

SYSTEM_PROMPT = """You are Forterra, an expert AI Security Architect for Terraform.

Security rules to enforce:
1. Encryption at rest (AES-256) and in transit (TLS 1.2+) for all resources
2. Private subnets by default. No 0.0.0.0/0 unless explicitly requested
3. Least-privilege IAM. No wildcard (*) permissions
4. Block public access on S3, RDS, EKS
5. Enable CloudTrail, VPC Flow Logs, access logging
6. Never hardcode secrets
7. Pin provider and module versions
8. Add security-relevant tags

Always respond with valid JSON only. No markdown, no backticks."""

GENERATE_PROMPT = """Generate secure Terraform for: {prompt}
Provider: {provider} | Compliance: {compliance}

Respond with JSON:
{{"success": true, "security_score": <0-100>, "score_grade": "<A+/A/B/C/D/F>",
"resources_count": <n>, "modules": ["<names>"],
"hardening_applied": ["<measures>"],
"files": {{"main.tf": "<code>", "variables.tf": "<code>", "outputs.tf": "<code>", "providers.tf": "<code>"}}}}"""

FIX_PROMPT = """Fix this Terraform security issue:
Severity: {severity} | Resource: {resource} | File: {file}
Issue: {message}
Code: {code}

Respond with JSON:
{{"success": true, "description": "<what was fixed>", "fixed_code": "<corrected terraform>"}}"""


class AIEngine:
    def __init__(self):
        self.api_key = os.getenv("FORTERRA_API_KEY") or os.getenv("ANTHROPIC_API_KEY")

    def has_api_key(self) -> bool:
        return bool(self.api_key)

    def generate_infrastructure(self, prompt: str, provider: str = "aws", compliance: list = None) -> dict:
        if not self.has_api_key():
            return {"success": False, "error": "No API key configured"}

        compliance_str = ", ".join(compliance) if compliance else "CIS"
        user_prompt = GENERATE_PROMPT.format(prompt=prompt, provider=provider, compliance=compliance_str)

        try:
            import anthropic
            client = anthropic.Anthropic(api_key=self.api_key)
            message = client.messages.create(
                model="claude-sonnet-4-20250514", max_tokens=4096,
                system=SYSTEM_PROMPT,
                messages=[{"role": "user", "content": user_prompt}],
            )
            response_text = "".join(b.text for b in message.content if hasattr(b, "text"))
            return json.loads(response_text.strip().replace("```json", "").replace("```", "").strip())
        except json.JSONDecodeError as e:
            return {"success": False, "error": f"Failed to parse AI response: {e}"}
        except Exception as e:
            return {"success": False, "error": str(e)}

    def generate_fix(self, issue: dict) -> dict:
        if not self.has_api_key():
            return {"success": False, "error": "No API key configured"}

        user_prompt = FIX_PROMPT.format(
            severity=issue.get("severity", "UNKNOWN"), resource=issue.get("resource", "unknown"),
            file=issue.get("file", "unknown"), message=issue.get("message", ""),
            code=issue.get("code", "# No code available"),
        )

        try:
            import anthropic
            client = anthropic.Anthropic(api_key=self.api_key)
            message = client.messages.create(
                model="claude-sonnet-4-20250514", max_tokens=2048,
                system=SYSTEM_PROMPT,
                messages=[{"role": "user", "content": user_prompt}],
            )
            response_text = "".join(b.text for b in message.content if hasattr(b, "text"))
            return json.loads(response_text.strip().replace("```json", "").replace("```", "").strip())
        except Exception as e:
            return {"success": False, "error": str(e)}
