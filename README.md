<p align="center">
  <img src="https://img.shields.io/badge/version-0.1.0--alpha-34d399?style=flat-square" />
  <img src="https://img.shields.io/badge/license-MIT-blue?style=flat-square" />
  <img src="https://img.shields.io/badge/terraform-%3E%3D1.5-844fba?style=flat-square&logo=terraform" />
  <img src="https://img.shields.io/badge/AI--powered-Claude-ff6b35?style=flat-square" />
</p>

<h1 align="center">
  🏰 Forterra
</h1>

<p align="center">
  <strong>AI Security Architect for Terraform</strong>
  <br />
  Generate production-grade, CIS-hardened Terraform from plain English.
  <br />
  Scan. Fix. Harden. Before it hits production.
</p>

<p align="center">
  <a href="#-quick-start">Quick Start</a> •
  <a href="#-features">Features</a> •
  <a href="#-how-it-works">How It Works</a> •
  <a href="#-cli-reference">CLI Reference</a> •
  <a href="#-github-action">GitHub Action</a> •
  <a href="#-contributing">Contributing</a>
</p>

---

## The Problem

> **63% of cloud security incidents stem from misconfigurations — not sophisticated attacks.**

Every DevOps team faces the same cycle:

1. Developer copy-pastes Terraform from a blog post or Stack Overflow
2. It works, gets merged, deployed to production
3. 6 months later, a security audit reveals public S3 buckets, overly permissive IAM roles, unencrypted databases, open security groups
4. Team spends weeks remediating — if they're lucky enough to find it before an attacker does

**Forterra breaks this cycle.** Instead of writing insecure Terraform and scanning it after the fact, Forterra generates secure-by-default infrastructure from the start — and continuously hardens everything in your pipeline.

## ⚡ Quick Start

### Install

```bash
# macOS / Linux
brew install forterra

# Or with npm
npm install -g @forterra/cli

# Or run directly
npx @forterra/cli generate "your architecture here"
```

### Generate Secure Terraform

```bash
# Describe what you need — Forterra handles the security
forterra generate "Three-tier web app on AWS with Postgres, Redis, and an ALB"
```

**Output:**
```
🔍 Analyzing architecture requirements...
🛡️  Applying CIS AWS Foundations Benchmark v3.0...
🔐 Enforcing least-privilege IAM policies...
📦 Generating modular Terraform structure...

✅ Generated 12 resources across 4 modules
   Security Score: 96/100 (A+)

📁 Output:
   ├── modules/
   │   ├── vpc/
   │   ├── compute/
   │   ├── database/
   │   └── iam/
   ├── main.tf
   ├── variables.tf
   ├── outputs.tf
   └── providers.tf
```

### Scan Existing Terraform

```bash
# Point Forterra at your existing infrastructure code
forterra scan ./infrastructure/

# Output:
# ⚠️  Found 3 issues in 47 resources:
#    CRITICAL: aws_s3_bucket.data — public access not blocked
#    HIGH: aws_rds_instance.main — encryption at rest disabled
#    MEDIUM: aws_security_group.web — port 22 open to 0.0.0.0/0
#
# 🔧 Run `forterra fix` to auto-remediate with AI
```

### Auto-Fix Issues

```bash
# AI-powered remediation — generates a fix PR automatically
forterra fix --auto-pr

# Or fix interactively
forterra fix --interactive
```

## 🚀 Features

### 🧠 AI-Powered Generation
Describe your cloud architecture in plain English. Forterra understands architecture patterns, security requirements, and compliance frameworks — not just keywords.

```bash
forterra generate "Production EKS cluster with private node groups, \
  Istio service mesh, and a Postgres RDS with automated backups"
```

### 🛡️ CIS Hardened by Default
Every generated resource follows CIS benchmarks out of the box:

- **Encryption** — at rest (AES-256) and in transit (TLS 1.2+) for all supported resources
- **Network isolation** — private subnets by default, minimal security group rules
- **IAM least privilege** — scoped roles and policies, no wildcard permissions
- **Logging & monitoring** — CloudTrail, VPC flow logs, access logging enabled
- **Public access blocked** — S3, RDS, EKS API all private unless explicitly requested

### 🔍 Security Scoring
Every generated plan and scan includes a security posture score:

```
┌────────────────────────────────────────┐
│  Security Score: 96/100  (A+)          │
│                                        │
│  ✅ Encryption at rest      (AES-256)  │
│  ✅ Encryption in transit   (TLS 1.3)  │
│  ✅ IAM least privilege     (scoped)   │
│  ✅ Network isolation       (private)  │
│  ✅ Logging enabled         (all)      │
│  ⚠️  Backup retention       (7 days)   │
│                                        │
│  Recommendation: Increase backup       │
│  retention to 30 days for production   │
└────────────────────────────────────────┘
```

### 🔧 AI Auto-Remediation
Don't just find problems — fix them:

```bash
forterra fix ./infrastructure/
# Analyzes each issue
# Generates minimal, targeted fixes
# Explains what changed and why
# Creates a PR with full context
```

### 📦 Modular Architecture
Generated code follows Terraform best practices:

```
output/
├── modules/
│   ├── vpc/
│   │   ├── main.tf
│   │   ├── variables.tf
│   │   └── outputs.tf
│   ├── compute/
│   ├── database/
│   └── iam/
├── environments/
│   ├── dev.tfvars
│   ├── staging.tfvars
│   └── prod.tfvars
├── main.tf
├── variables.tf
├── outputs.tf
├── providers.tf
├── backend.tf
└── versions.tf
```

### 🔗 CI/CD Integration
Block insecure infrastructure from reaching production:

```yaml
# .github/workflows/forterra.yml
name: Forterra Security Scan
on: [pull_request]

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: forterra-ai/scan-action@v1
        with:
          path: ./infrastructure/
          fail-on: high  # Block PRs with HIGH or CRITICAL issues
          auto-fix: true # Generate fix suggestions as PR comments
```

## 🏗️ How It Works

```
┌──────────────────┐     ┌──────────────────┐     ┌──────────────────┐
│                  │     │                  │     │                  │
│  1. DESCRIBE     │────▶│  2. ANALYZE      │────▶│  3. GENERATE     │
│                  │     │                  │     │                  │
│  Plain English   │     │  AI understands  │     │  Secure, modular │
│  architecture    │     │  intent, applies │     │  Terraform with  │
│  description     │     │  security policy │     │  CIS hardening   │
│                  │     │                  │     │                  │
└──────────────────┘     └──────────────────┘     └──────────────────┘
                                                          │
                                                          ▼
┌──────────────────┐     ┌──────────────────┐     ┌──────────────────┐
│                  │     │                  │     │                  │
│  6. MONITOR      │◀────│  5. DEPLOY       │◀────│  4. REVIEW       │
│                  │     │                  │     │                  │
│  Continuous      │     │  Apply with      │     │  Security score, │
│  drift detection │     │  confidence via  │     │  hardening report │
│  & alerting      │     │  terraform apply │     │  & explanations  │
│                  │     │                  │     │                  │
└──────────────────┘     └──────────────────┘     └──────────────────┘
```

## 📖 CLI Reference

| Command | Description |
|---|---|
| `forterra generate "<prompt>"` | Generate secure Terraform from a description |
| `forterra scan <path>` | Scan existing Terraform for security issues |
| `forterra fix [path]` | AI-powered auto-remediation of detected issues |
| `forterra fix --auto-pr` | Generate a GitHub PR with fixes |
| `forterra score <path>` | Get a security score for your infrastructure |
| `forterra policy init` | Initialize custom organization policies |
| `forterra policy add "<rule>"` | Add a natural language security policy |
| `forterra audit <path>` | Generate a compliance audit report (SOC2, PCI-DSS, HIPAA) |
| `forterra drift` | Check for security-impacting drift |

## 🔌 Supported Providers

| Provider | Generate | Scan | Fix |
|---|---|---|---|
| AWS | ✅ | ✅ | ✅ |
| Azure | ✅ | ✅ | ✅ |
| GCP | ✅ | ✅ | 🚧 |
| Kubernetes | 🚧 | ✅ | 🚧 |

## 🔐 Compliance Frameworks

- **CIS AWS Foundations Benchmark v3.0**
- **CIS Azure Foundations Benchmark v2.1**
- **CIS GCP Foundations Benchmark v2.0**
- **SOC 2 Type II**
- **PCI-DSS v4.0**
- **HIPAA**
- **NIST 800-53**

## 🏛️ Architecture

```
forterra/
├── cmd/                    # CLI entry points
│   ├── generate.go
│   ├── scan.go
│   ├── fix.go
│   └── root.go
├── pkg/
│   ├── ai/                 # AI engine (prompt construction, response parsing)
│   │   ├── architect.go    # Architecture understanding & generation
│   │   ├── remediator.go   # Issue fixing & PR generation
│   │   └── scorer.go       # Security scoring engine
│   ├── scanner/            # Static analysis engine
│   │   ├── terraform.go    # HCL parsing & analysis
│   │   ├── policies/       # Built-in security policies
│   │   └── rules/          # CIS benchmark rules
│   ├── generator/          # Terraform code generation
│   │   ├── modules.go      # Module scaffolding
│   │   ├── hardening.go    # Security hardening transforms
│   │   └── templates/      # Resource templates
│   ├── compliance/         # Compliance framework mappings
│   └── output/             # Output formatters (terminal, JSON, SARIF)
├── policies/               # Default policy library (YAML)
├── action/                 # GitHub Action
│   ├── action.yml
│   └── entrypoint.sh
├── web/                    # Web playground (React)
├── docs/                   # Documentation
├── Makefile
├── go.mod
└── README.md
```

## 💰 Pricing

| | Free | Pro | Enterprise |
|---|---|---|---|
| **Price** | $0 forever | $29/mo | Custom |
| Generate | 10/month | Unlimited | Unlimited |
| Scan | Unlimited | Unlimited | Unlimited |
| Auto-fix PRs | 5/month | Unlimited | Unlimited |
| Compliance reports | — | ✅ | ✅ |
| Custom policies | — | ✅ | ✅ |
| Team dashboard | — | ✅ | ✅ |
| SSO / SAML | — | — | ✅ |
| SLA | — | — | ✅ |

## 🤝 Contributing

We love contributions! See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

```bash
# Clone the repo
git clone https://github.com/forterra-ai/forterra.git
cd forterra

# Install dependencies
make setup

# Run tests
make test

# Build
make build
```

## 📄 License

MIT — see [LICENSE](LICENSE) for details.

---

<p align="center">
  <strong>Built with 🛡️ by the Forterra team</strong>
  <br />
  <a href="https://forterra.dev">Website</a> •
  <a href="https://docs.forterra.dev">Docs</a> •
  <a href="https://twitter.com/forterra_ai">Twitter</a> •
  <a href="https://discord.gg/forterra">Discord</a>
</p>
