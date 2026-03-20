<p align="center">
  <img src="https://img.shields.io/badge/version-0.1.0-34d399?style=flat-square" />
  <img src="https://img.shields.io/badge/license-MIT-blue?style=flat-square" />
  <img src="https://img.shields.io/badge/terraform-%3E%3D1.5-844fba?style=flat-square&logo=terraform" />
  <img src="https://img.shields.io/badge/python-%3E%3D3.9-3776AB?style=flat-square&logo=python" />
</p>

<h1 align="center">🏰 Forterra</h1>

<p align="center">
  <strong>AI-powered Terraform plan analyzer & security trainer</strong><br/>
  Catch dangerous changes before they hit production. Learn why they're dangerous.
</p>

<p align="center">
  <a href="#-plan-analyzer">Plan Analyzer</a> •
  <a href="#-security-trainer">Security Trainer</a> •
  <a href="#-scanner">Scanner</a> •
  <a href="#-install">Install</a> •
  <a href="#-github-action">GitHub Action</a>
</p>

---

## The Problem

**63% of cloud security incidents come from misconfigurations.** Not sophisticated attacks. Misconfigurations.

Tools like Checkov and Trivy scan your `.tf` files for known issues. But they don't analyze what Terraform is **actually about to do**. A `terraform plan` with 500 lines of output and a database destroy-and-recreate buried on line 347? That's on you to catch.

Forterra fills two gaps:

1. **Plan analysis** — scans `terraform plan` output and classifies every change by risk. Catches resource replacements that cause downtime, security groups being opened wider, IAM policies gaining wildcard permissions.

2. **Security training** — instead of cryptic rule IDs, teaches you *why* something is a risk with real attack scenarios, breach references, and fix code.

---

## 🔍 Plan Analyzer

```bash
terraform plan -out=tfplan
terraform show -json tfplan > plan.json
forterra analyze plan.json
```

```
📊 Plan Analysis Summary
Risk Score: 16/100 (CRITICAL)
7 resources changing: +1 create  ~5 update  -0 destroy  ±1 replace

🔴 DANGEROUS CHANGES:
  REPLACE: aws_db_instance.prod
    → Database destruction can cause permanent data loss
    → ⚠️  THIS WILL LIKELY CAUSE DOWNTIME

🔒 SECURITY ISSUES:
  CRITICAL: aws_iam_role_policy.lambda_permissions
    IAM policy now includes wildcard (*) permissions

🟢 SAFE CHANGES (3):
  CREATE: aws_s3_bucket.logs
  UPDATE: aws_instance.worker
  UPDATE: aws_cloudwatch_log_group.app
```

What it catches that static scanners can't: destroy-and-recreate on databases and clusters (downtime risk), security groups opening wider, IAM wildcard escalation, DNS changes, and data-bearing resource destruction.

Block dangerous plans in CI:

```bash
forterra analyze plan.json --fail-on high
```

---

## 📚 Security Trainer

```bash
forterra learn ./infrastructure/
```

For every issue, you get the attack scenario, real-world breaches, fix code, and CIS benchmark reference:

```
❌ CRITICAL: aws_s3_bucket.data — public-read ACL

  🎯 ATTACK SCENARIO:
     Attacker uses BucketFinder to scan for public S3 buckets.
     Your bucket shows up. They download everything.

  📰 REAL-WORLD BREACHES:
     Capital One (2019) — 100M records exposed
     Twitch (2021) — Source code and earnings leaked

  🔧 FIX: [copy-paste Terraform code]
  📚 CIS AWS Foundations v3.0 — Rule 2.1.1
```

Browse lessons:

```bash
forterra learn --list-rules
forterra learn --rule FT-S3-001
```

---

## 🛡️ Scanner

Offline scanning, no API key needed:

```bash
forterra scan ./infrastructure/
forterra score ./infrastructure/
```

---

## ⚙️ Install

```bash
pip install forterra
```

From source:

```bash
git clone https://github.com/YOUR_USERNAME/forterra.git
cd forterra
pip install -e .
```

The core features (`analyze`, `learn`, `scan`, `score`) work without an API key.

For AI-powered generation and auto-fix, set an Anthropic API key:

```bash
export FORTERRA_API_KEY=sk-ant-your-key
```

---

## 🔗 GitHub Action

```yaml
name: Forterra Security Check
on: [pull_request]

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: YOUR_USERNAME/forterra@main
        with:
          path: ./infrastructure/
          fail-on: high
```

---

## 📖 Commands

| Command | API Key? | Description |
|---|---|---|
| `forterra analyze <plan.json>` | No | Analyze terraform plan for dangerous changes |
| `forterra learn <path>` | No | Scan and teach with attack scenarios |
| `forterra scan <path>` | No | Scan for misconfigurations |
| `forterra score <path>` | No | Security score |
| `forterra generate "<prompt>"` | Yes | Generate secure Terraform from English |
| `forterra fix <path>` | Yes | AI auto-remediation |

---

## 🤝 Contributing

```bash
git clone https://github.com/YOUR_USERNAME/forterra.git
cd forterra && python3 -m venv venv && source venv/bin/activate
pip install -e ".[dev]" && pytest tests/ -v
```

Add scanner rules in `forterra/scanner.py`. Add attack scenarios in `forterra/learn.py`.

## 📄 License

MIT
