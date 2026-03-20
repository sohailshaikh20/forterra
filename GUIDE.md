# 🏰 Forterra — Complete Step-by-Step Guide

This guide explains EVERYTHING about how Forterra works, how to set it up,
how to put it on GitHub, and how users will install and use it.

---

## 📁 What Each File Does

```
forterra/
├── pyproject.toml          ← PACKAGE CONFIG: Tells Python how to install this tool
│                              Defines the name "forterra", version, dependencies,
│                              and most importantly: the CLI entry point
│                              (line: forterra = "forterra.cli:cli")
│
├── forterra/               ← THE ACTUAL APP CODE
│   ├── __init__.py         ← Makes this a Python package + stores version number
│   ├── cli.py              ← ALL TERMINAL COMMANDS live here (generate, scan, fix, score)
│   ├── ai_engine.py        ← TALKS TO CLAUDE API (sends prompts, parses responses)
│   ├── scanner.py          ← OFFLINE SECURITY SCANNER (checks .tf files against rules)
│   └── generator.py        ← WRITES FILES TO DISK (creates the output directory)
│
├── tests/                  ← AUTOMATED TESTS
│   └── test_scanner.py     ← Tests that the scanner catches security issues
│
├── action.yml              ← GITHUB ACTION: So users can add Forterra to their CI/CD
├── .env.example            ← Example environment variables
├── .gitignore              ← Files Git should ignore
├── .forterra.yml           ← Example project config (created by `forterra init`)
├── Makefile                ← Shortcuts for common dev tasks
├── LICENSE                 ← MIT license
└── README.md               ← The main GitHub page
```

---

## 🚀 STEP 1: Set Up Your Local Development Environment

### Prerequisites
- Python 3.9+ installed (check with: `python3 --version`)
- Git installed (check with: `git --version`)
- A GitHub account

### Setup Commands

```bash
# 1. Navigate to the forterra project folder
cd forterra

# 2. Create a virtual environment (isolates Python packages)
python3 -m venv venv

# 3. Activate the virtual environment
#    On Mac/Linux:
source venv/bin/activate
#    On Windows:
#    venv\Scripts\activate

# 4. Install Forterra in "editable" mode (-e means changes you make to
#    the code take effect immediately without reinstalling)
pip install -e ".[dev]"

# 5. Verify it works — you should see the help text
forterra --help

# 6. Try the scanner (no API key needed!)
forterra scan .
```

**What "editable mode" means:** When you run `pip install -e .`, Python creates
a link from your terminal's `forterra` command to YOUR code in this folder.
So when you edit `cli.py` or `scanner.py`, the changes are live immediately.
No need to reinstall.

---

## 🔑 STEP 2: Set Up the AI Features

The `scan` and `score` commands work WITHOUT an API key (they're offline).
The `generate` and `fix` commands need a Claude API key.

```bash
# 1. Go to https://console.anthropic.com and sign up
# 2. Create an API key
# 3. Set it as an environment variable:

export FORTERRA_API_KEY=sk-ant-your-key-here

# Or create a .env file (the tool will read it automatically):
cp .env.example .env
# Then edit .env and paste your key

# 4. Try generating secure Terraform:
forterra generate "VPC with two private subnets on AWS"
```

---

## 📤 STEP 3: Put It on GitHub

```bash
# 1. Create a new repository on GitHub
#    Go to https://github.com/new
#    Name: forterra
#    Description: AI Security Architect for Terraform
#    Public repo ✓
#    DON'T add a README (we already have one)

# 2. Initialize git and push
cd forterra
git init
git add .
git commit -m "🏰 Initial commit — Forterra v0.1.0"
git branch -M main
git remote add origin https://github.com/YOUR_USERNAME/forterra.git
git push -u origin main
```

---

## 🌐 STEP 4: Free Hosting for the Landing Page

**You DON'T need a domain!** Here are free options:

### Option A: Vercel (Easiest — same as your friend's site)
1. Go to https://vercel.com and sign in with GitHub
2. Click "New Project"
3. Import your forterra repo
4. It auto-deploys and gives you a URL like: `forterra.vercel.app`
5. FREE. No domain needed.

### Option B: GitHub Pages (100% free, attached to your repo)
1. Create a `/docs` folder in your repo
2. Put an `index.html` version of the landing page there
3. Go to repo Settings → Pages → Source: main, folder: /docs
4. Your site is live at: `YOUR_USERNAME.github.io/forterra`

### Option C: Netlify (also free)
1. Go to https://netlify.com
2. Connect your GitHub repo
3. Auto-deploys. Free URL: `forterra.netlify.app`

**I recommend Vercel** since your friend already uses it and you know how it works.

---

## 👥 STEP 5: How Users Install and Use Forterra

### From PyPI (after you publish — see Step 7)
```bash
pip install forterra
forterra --help
```

### From GitHub directly (works right now!)
```bash
pip install git+https://github.com/YOUR_USERNAME/forterra.git
forterra --help
```

### As a GitHub Action (for CI/CD)
Users add this to their repo:

```yaml
# .github/workflows/forterra.yml
name: Forterra Security Scan
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

## 🧪 STEP 6: How to Make Changes

### To add a new security rule (scanner):
Edit `forterra/scanner.py` and add a new entry to `SECURITY_RULES`:

```python
{
    "id": "FT-NEW-001",
    "severity": "HIGH",
    "resource_pattern": r'resource\s+"aws_something"',
    "vuln_pattern": r'some_bad_config\s*=\s*true',
    "message": "Description of the security issue",
    "fix_hint": "How to fix it",
},
```

### To change what the AI generates:
Edit the `SYSTEM_PROMPT` in `forterra/ai_engine.py`. This is the instruction
that tells Claude how to behave. Add or change the security rules there.

### To add a new CLI command:
Add a new function in `forterra/cli.py`:

```python
@cli.command()
@click.argument("something")
def my_new_command(something):
    """Description of my command."""
    console.print(f"Doing something with {something}")
```

Now `forterra my-new-command "hello"` works.

### To run tests:
```bash
pytest tests/ -v
```

### To test your changes locally:
Since you installed in editable mode, just run:
```bash
forterra scan .    # Your changes are live immediately
```

---

## 📦 STEP 7: Publishing to PyPI (so users can `pip install forterra`)

This is how you make `pip install forterra` work for everyone:

```bash
# 1. Create a PyPI account at https://pypi.org/account/register/

# 2. Install build tools
pip install build twine

# 3. Build the package
python -m build
# This creates dist/forterra-0.1.0.tar.gz and dist/forterra-0.1.0-*.whl

# 4. Upload to Test PyPI first (to make sure it works)
python -m twine upload --repository testpypi dist/*
# Test it: pip install --index-url https://test.pypi.org/simple/ forterra

# 5. Upload to real PyPI
python -m twine upload dist/*

# Now anyone in the world can run:
#   pip install forterra
#   forterra --help
```

---

## 📊 STEP 8: Getting GitHub Stars & Users

1. **Add GitHub Topics:** Go to your repo → About → Add topics:
   `terraform`, `security`, `iac`, `devops`, `ai`, `infrastructure-as-code`,
   `cloud-security`, `cli`, `hacktoberfest`

2. **Post on Reddit:** r/terraform, r/devops, r/aws, r/cloudcomputing

3. **Post on HackerNews:** "Show HN: Forterra — AI Security Architect for Terraform"

4. **Post on Twitter/X:** Tag @HashiCorp, @awscloud, DevOps influencers

5. **Post on Dev.to:** Write an article about Terraform security

6. **Product Hunt:** Launch when you have a polished web demo

---

## 🔄 How the Whole Flow Works (End to End)

```
USER TYPES:                              WHAT HAPPENS:
─────────────────────────────────────────────────────────────────

pip install forterra                     Python downloads the package
                                         Creates the `forterra` command
                                         (linked to forterra/cli.py → cli())

forterra generate "VPC on AWS"           cli.py → generate() function runs
                                         → AIEngine.generate_infrastructure()
                                         → Sends prompt to Claude API
                                         → Claude returns JSON with Terraform
                                         → Generator writes .tf files to disk
                                         → CLI shows security score

forterra scan ./infrastructure/          cli.py → scan() function runs
                                         → Scanner.find_terraform_files()
                                         → Scanner.scan_files()
                                         → Checks each .tf against SECURITY_RULES
                                         → Returns list of issues
                                         → CLI displays them with colors

forterra fix ./infrastructure/           cli.py → fix() function runs
                                         → First runs Scanner to find issues
                                         → For each issue, calls AIEngine.generate_fix()
                                         → Claude suggests a fix
                                         → Fix is applied to the file

forterra score ./infrastructure/         cli.py → score() function runs
                                         → Runs Scanner
                                         → Calculates score from issues
                                         → Displays score card
```

---

## ❓ FAQ

**Q: Do I need to know Go?**
No! The tool is written in Python. I chose Python because it's easier to modify,
and the DevOps community uses Python extensively.

**Q: Is the Anthropic API free?**
They have a free tier with limited credits. For development, it's enough.
For production, you'd pass the cost to users (they bring their own API key).

**Q: Can I change the AI model?**
Yes! In `ai_engine.py`, change the `model` parameter. You could even add
support for OpenAI, local models, etc.

**Q: How is this different from Checkov?**
Checkov only SCANS. Forterra GENERATES secure code from scratch and AUTO-FIXES
issues. The scanner is just one feature.

**Q: Do I need a domain?**
No. Use `forterra.vercel.app` or `yourname.github.io/forterra` for free.
