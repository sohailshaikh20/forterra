"""
Forterra CLI — The main entry point for all terminal commands.

HOW THIS WORKS:
- We use "Click" library to define commands (generate, scan, fix, score)
- Each command is a Python function decorated with @cli.command()
- When a user types `forterra generate "..."`, Click routes it to the generate() function
- We use "Rich" library to make the terminal output look beautiful (colors, tables, progress bars)
"""

import click
import os
import sys
import json
from pathlib import Path

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.syntax import Syntax
from rich.markdown import Markdown
from rich import print as rprint

from forterra import __version__
from forterra.ai_engine import AIEngine
from forterra.scanner import Scanner
from forterra.generator import Generator

# Rich console for pretty terminal output
console = Console()


# ============================================================
# MAIN CLI GROUP
# This is the root command. All subcommands attach to this.
# When user types just `forterra`, they see help text.
# ============================================================
@click.group()
@click.version_option(version=__version__, prog_name="forterra")
def cli():
    """
    🏰 Forterra — AI Security Architect for Terraform

    Generate production-grade, CIS-hardened Terraform from plain English.
    Scan, fix, and harden your infrastructure before it hits production.
    """
    pass


# ============================================================
# COMMAND: forterra generate "..."
# This is the main feature — takes a plain English description
# and generates secure Terraform code.
# ============================================================
@cli.command()
@click.argument("prompt")
@click.option("--output", "-o", default="./forterra-output", help="Output directory for generated Terraform")
@click.option("--provider", "-p", default="aws", type=click.Choice(["aws", "azure", "gcp"]), help="Cloud provider")
@click.option("--compliance", "-c", multiple=True, help="Compliance frameworks to apply (cis, soc2, hipaa, pci)")
@click.option("--dry-run", is_flag=True, help="Show what would be generated without writing files")
def generate(prompt, output, provider, compliance, dry_run):
    """Generate secure Terraform from a plain English description.

    Example:
        forterra generate "Three-tier web app on AWS with Postgres and Redis"
    """
    console.print()
    console.print(Panel(
        f"[bold white]🏰 Forterra — AI Security Architect[/bold white]\n"
        f"[dim]Generating secure Terraform for:[/dim]\n"
        f'[cyan]"{prompt}"[/cyan]',
        border_style="green",
    ))
    console.print()

    # Check for API key
    ai = AIEngine()
    if not ai.has_api_key():
        console.print("[red]❌ No API key found.[/red]")
        console.print()
        console.print("Set your Anthropic API key:")
        console.print("  [cyan]export FORTERRA_API_KEY=your-key-here[/cyan]")
        console.print()
        console.print("Or create a [cyan].env[/cyan] file in your project root:")
        console.print("  [cyan]FORTERRA_API_KEY=your-key-here[/cyan]")
        console.print()
        console.print("Get a key at: [link]https://console.anthropic.com[/link]")
        sys.exit(1)

    # Show progress while AI is working
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
    ) as progress:
        # Step 1: Analyze
        task = progress.add_task("🔍 Analyzing architecture requirements...", total=None)
        result = ai.generate_infrastructure(prompt, provider, list(compliance))
        progress.update(task, description="🔍 Architecture analyzed ✓")

        # Step 2: Apply hardening
        progress.add_task("🛡️  Applying CIS hardening policies...", total=None)
        progress.add_task("🔐 Enforcing least-privilege IAM...", total=None)
        progress.add_task("📦 Generating modular Terraform...", total=None)

    if not result.get("success"):
        console.print(f"\n[red]❌ Generation failed: {result.get('error', 'Unknown error')}[/red]")
        sys.exit(1)

    # Display security score
    console.print()
    score = result.get("security_score", 0)
    grade = result.get("score_grade", "?")
    score_color = "green" if score >= 90 else "yellow" if score >= 70 else "red"

    score_table = Table(show_header=False, border_style=score_color, padding=(0, 2))
    score_table.add_column(style="bold")
    score_table.add_column()
    score_table.add_row(f"Security Score", f"[bold {score_color}]{score}/100 ({grade})[/bold {score_color}]")
    score_table.add_row(f"Resources", f"{result.get('resources_count', 0)}")
    score_table.add_row(f"Modules", f"{', '.join(result.get('modules', []))}")
    console.print(Panel(score_table, title="[bold]📊 Security Report[/bold]", border_style=score_color))

    # Display hardening applied
    console.print()
    console.print("[bold]🛡️  Security Hardening Applied:[/bold]")
    for item in result.get("hardening_applied", []):
        console.print(f"  [green]✓[/green] {item}")

    # Write files (or show dry run)
    if dry_run:
        console.print("\n[yellow]🔸 Dry run — showing generated code without writing files:[/yellow]\n")
        for filename, content in result.get("files", {}).items():
            console.print(f"[bold cyan]📄 {filename}[/bold cyan]")
            syntax = Syntax(content, "hcl", theme="monokai", line_numbers=True)
            console.print(syntax)
            console.print()
    else:
        # Write the actual files
        generator = Generator()
        output_path = Path(output)
        written_files = generator.write_files(output_path, result.get("files", {}))

        console.print(f"\n[bold green]✅ Generated {len(written_files)} files in {output_path}/[/bold green]\n")
        console.print("[bold]📁 Output:[/bold]")
        for f in written_files:
            console.print(f"   [dim]├──[/dim] {f}")

    console.print()
    console.print("[dim]Run [cyan]terraform init && terraform plan[/cyan] to preview your infrastructure.[/dim]")
    console.print()


# ============================================================
# COMMAND: forterra scan <path>
# Scans existing Terraform files for security issues.
# ============================================================
@cli.command()
@click.argument("path", default=".", type=click.Path(exists=True))
@click.option("--format", "-f", "output_format", default="pretty", type=click.Choice(["pretty", "json", "sarif"]))
@click.option("--fail-on", type=click.Choice(["critical", "high", "medium", "low"]), default=None,
              help="Exit with error code if issues at this severity or above are found")
def scan(path, output_format, fail_on):
    """Scan existing Terraform files for security issues.

    Example:
        forterra scan ./infrastructure/
        forterra scan . --fail-on high
    """
    console.print()
    console.print(f"[bold]🔍 Scanning [cyan]{path}[/cyan] for security issues...[/bold]")
    console.print()

    scanner = Scanner()
    tf_files = scanner.find_terraform_files(path)

    if not tf_files:
        console.print(f"[yellow]⚠️  No Terraform files found in {path}[/yellow]")
        sys.exit(0)

    console.print(f"[dim]Found {len(tf_files)} Terraform file(s)[/dim]")
    console.print()

    # Run scan
    issues = scanner.scan_files(tf_files)

    if not issues:
        console.print("[bold green]✅ No security issues found! Your Terraform looks secure.[/bold green]")
        console.print()
        return

    # Display issues
    severity_colors = {
        "CRITICAL": "red bold",
        "HIGH": "red",
        "MEDIUM": "yellow",
        "LOW": "blue",
    }

    severity_order = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]
    issues_sorted = sorted(issues, key=lambda x: severity_order.index(x.get("severity", "LOW")))

    console.print(f"[bold yellow]⚠️  Found {len(issues)} issue(s):[/bold yellow]")
    console.print()

    for issue in issues_sorted:
        sev = issue["severity"]
        color = severity_colors.get(sev, "white")
        console.print(f"  [{color}]{sev}[/{color}]: {issue['resource']} — {issue['message']}")
        if issue.get("fix_hint"):
            console.print(f"          [dim]💡 {issue['fix_hint']}[/dim]")

    console.print()
    console.print("[dim]Run [cyan]forterra fix[/cyan] to auto-remediate with AI.[/dim]")
    console.print()

    # Exit with error if --fail-on is set
    if fail_on:
        severity_levels = {"critical": 0, "high": 1, "medium": 2, "low": 3}
        threshold = severity_levels[fail_on]
        for issue in issues:
            issue_level = severity_levels.get(issue["severity"].lower(), 3)
            if issue_level <= threshold:
                sys.exit(1)


# ============================================================
# COMMAND: forterra fix <path>
# AI-powered auto-remediation of security issues.
# ============================================================
@cli.command()
@click.argument("path", default=".", type=click.Path(exists=True))
@click.option("--auto-pr", is_flag=True, help="Automatically create a GitHub PR with fixes")
@click.option("--interactive", "-i", is_flag=True, help="Review each fix before applying")
def fix(path, auto_pr, interactive):
    """Auto-fix security issues with AI-powered remediation.

    Example:
        forterra fix ./infrastructure/
        forterra fix --auto-pr
    """
    console.print()
    console.print(f"[bold]🔧 Scanning and fixing [cyan]{path}[/cyan]...[/bold]")
    console.print()

    # First scan
    scanner = Scanner()
    tf_files = scanner.find_terraform_files(path)
    issues = scanner.scan_files(tf_files)

    if not issues:
        console.print("[bold green]✅ No issues to fix![/bold green]")
        return

    console.print(f"[yellow]Found {len(issues)} issue(s) to fix.[/yellow]")
    console.print()

    ai = AIEngine()
    if not ai.has_api_key():
        console.print("[red]❌ API key required for AI-powered fixes.[/red]")
        console.print("  [cyan]export FORTERRA_API_KEY=your-key-here[/cyan]")
        sys.exit(1)

    for issue in issues:
        console.print(f"  [bold]{issue['severity']}[/bold]: {issue['resource']} — {issue['message']}")

        if interactive:
            fix_it = click.confirm("    Apply fix?", default=True)
            if not fix_it:
                console.print("    [dim]Skipped[/dim]")
                continue

        with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}"), console=console) as prog:
            prog.add_task("    Generating fix...", total=None)
            fix_result = ai.generate_fix(issue)

        if fix_result.get("success"):
            console.print(f"    [green]✓ Fixed: {fix_result.get('description', 'Applied security fix')}[/green]")
        else:
            console.print(f"    [red]✗ Could not auto-fix: {fix_result.get('error', 'Unknown')}[/red]")

        console.print()

    if auto_pr:
        console.print("[bold]📤 Creating GitHub PR with fixes...[/bold]")
        console.print("[yellow]⚠️  GitHub PR integration coming in v0.2.0[/yellow]")

    console.print()


# ============================================================
# COMMAND: forterra score <path>
# Quick security score for your Terraform.
# ============================================================
@cli.command()
@click.argument("path", default=".", type=click.Path(exists=True))
def score(path):
    """Get a security score for your Terraform infrastructure.

    Example:
        forterra score ./infrastructure/
    """
    console.print()
    console.print(f"[bold]📊 Scoring [cyan]{path}[/cyan]...[/bold]")
    console.print()

    scanner = Scanner()
    tf_files = scanner.find_terraform_files(path)

    if not tf_files:
        console.print(f"[yellow]⚠️  No Terraform files found in {path}[/yellow]")
        sys.exit(0)

    issues = scanner.scan_files(tf_files)
    total_resources = scanner.count_resources(tf_files)

    # Calculate score
    deductions = sum(
        {"CRITICAL": 20, "HIGH": 10, "MEDIUM": 5, "LOW": 2}.get(i["severity"], 0)
        for i in issues
    )
    score_val = max(0, 100 - deductions)
    grade = "A+" if score_val >= 95 else "A" if score_val >= 90 else "B" if score_val >= 80 else "C" if score_val >= 70 else "D" if score_val >= 60 else "F"
    color = "green" if score_val >= 90 else "yellow" if score_val >= 70 else "red"

    console.print(Panel(
        f"[bold {color}]Security Score: {score_val}/100 ({grade})[/bold {color}]\n\n"
        f"Files scanned: {len(tf_files)}\n"
        f"Resources found: {total_resources}\n"
        f"Issues found: {len(issues)}\n"
        f"  Critical: {sum(1 for i in issues if i['severity'] == 'CRITICAL')}\n"
        f"  High: {sum(1 for i in issues if i['severity'] == 'HIGH')}\n"
        f"  Medium: {sum(1 for i in issues if i['severity'] == 'MEDIUM')}\n"
        f"  Low: {sum(1 for i in issues if i['severity'] == 'LOW')}",
        title="[bold]🏰 Forterra Security Score[/bold]",
        border_style=color,
    ))
    console.print()


# ============================================================
# COMMAND: forterra init
# Initialize Forterra in a project.
# ============================================================
@cli.command()
def init():
    """Initialize Forterra in your project.

    Creates a .forterra.yml config file with your preferences.
    """
    console.print()
    console.print("[bold]🏰 Initializing Forterra...[/bold]")
    console.print()

    config_path = Path(".forterra.yml")
    if config_path.exists():
        console.print("[yellow]⚠️  .forterra.yml already exists. Use --force to overwrite.[/yellow]")
        return

    default_config = """# Forterra Configuration
# https://github.com/YOUR_USERNAME/forterra

# Default cloud provider
provider: aws

# Compliance frameworks to enforce
compliance:
  - cis

# Security scan settings
scan:
  # Minimum severity to report (low, medium, high, critical)
  min_severity: medium
  # Fail CI/CD pipeline on these severities
  fail_on: high

# Generation settings
generate:
  # Output directory
  output_dir: ./infrastructure
  # Include examples and comments in generated code
  include_comments: true
  # Generate tfvars files for environments
  environments:
    - dev
    - staging
    - prod
"""

    config_path.write_text(default_config)
    console.print(f"[green]✅ Created [cyan].forterra.yml[/cyan][/green]")
    console.print()
    console.print("[dim]Edit this file to customize Forterra for your project.[/dim]")
    console.print()


# ============================================================
# COMMAND: forterra analyze <plan.json>
# THE CORE PRODUCT — Analyzes terraform plan output for risks.
# This is what makes Forterra different from Checkov/Trivy.
# They scan static .tf files. Forterra scans the PLAN.
# ============================================================
@cli.command()
@click.argument("plan_file", required=False)
@click.option("--stdin", is_flag=True, help="Read plan JSON from stdin (for piping)")
@click.option("--format", "-f", "output_format", default="pretty", type=click.Choice(["pretty", "json"]))
@click.option("--fail-on", type=click.Choice(["critical", "high", "medium", "low"]), default=None,
              help="Exit with error code if risk level meets or exceeds threshold")
def analyze(plan_file, stdin, output_format, fail_on):
    """Analyze a Terraform plan for security risks and dangerous changes.

    The killer feature — catches what static scanners miss.

    Examples:
        terraform show -json tfplan > plan.json && forterra analyze plan.json
        terraform show -json tfplan | forterra analyze --stdin
        forterra analyze plan.json --fail-on high
    """
    from forterra.plan_analyzer import PlanAnalyzer

    console.print()
    console.print(Panel(
        "[bold white]🏰 Forterra — Plan Security Analyzer[/bold white]\n"
        "[dim]Analyzing what Terraform is about to do...[/dim]",
        border_style="green",
    ))
    console.print()

    analyzer = PlanAnalyzer()

    # Load plan data
    if stdin or (not plan_file and not sys.stdin.isatty()):
        console.print("[dim]Reading plan from stdin...[/dim]")
        plan_data = analyzer.load_plan_from_stdin()
        if not plan_data:
            console.print("[red]❌ Could not parse JSON from stdin.[/red]")
            console.print("[dim]Usage: terraform show -json tfplan | forterra analyze --stdin[/dim]")
            sys.exit(1)
        result = analyzer.analyze_plan_data(plan_data)
    elif plan_file:
        result = analyzer.analyze_plan(plan_file)
    else:
        console.print("[red]❌ No plan file provided.[/red]")
        console.print()
        console.print("[bold]Usage:[/bold]")
        console.print("  [cyan]# Option 1: Save plan to JSON first[/cyan]")
        console.print("  terraform plan -out=tfplan")
        console.print("  terraform show -json tfplan > plan.json")
        console.print("  forterra analyze plan.json")
        console.print()
        console.print("  [cyan]# Option 2: Pipe directly[/cyan]")
        console.print("  terraform show -json tfplan | forterra analyze --stdin")
        sys.exit(1)

    if not result.get("success"):
        console.print(f"[red]❌ Analysis failed: {result.get('error', 'Unknown error')}[/red]")
        sys.exit(1)

    # JSON output mode
    if output_format == "json":
        console.print(json.dumps(result, indent=2, default=str))
        return

    # Pretty output
    risk_score = result["risk_score"]
    risk_level = result["risk_level"]
    summary = result["summary"]

    # Risk score color
    if risk_level == "CRITICAL":
        risk_color = "red bold"
    elif risk_level == "HIGH":
        risk_color = "red"
    elif risk_level == "MEDIUM":
        risk_color = "yellow"
    else:
        risk_color = "green"

    # Summary panel
    summary_text = (
        f"[{risk_color}]Risk Score: {risk_score}/100 ({risk_level})[/{risk_color}]\n"
        f"{summary['total']} resources changing: "
        f"[green]+{summary['create']} create[/green]  "
        f"[yellow]~{summary['update']} update[/yellow]  "
        f"[red]-{summary['delete']} destroy[/red]  "
        f"[red bold]±{summary['replace']} replace[/red bold]"
    )
    console.print(Panel(summary_text, title="[bold]📊 Plan Analysis Summary[/bold]", border_style=risk_color.split()[0]))
    console.print()

    # Dangerous changes
    if result["dangerous_changes"]:
        console.print("[red bold]🔴 DANGEROUS CHANGES — Review carefully:[/red bold]")
        console.print()
        for change in result["dangerous_changes"]:
            action_label = change.get("action", "unknown").upper()
            console.print(f"  [red bold]{action_label}[/red bold]: [white]{change['address']}[/white]")
            for reason in change.get("reasons", []):
                console.print(f"    [red]→ {reason}[/red]")
            console.print()

    # Security issues
    if result["security_issues"]:
        console.print("[red bold]🔒 SECURITY ISSUES DETECTED:[/red bold]")
        console.print()
        for issue in result["security_issues"]:
            sev_color = {"CRITICAL": "red bold", "HIGH": "red", "MEDIUM": "yellow", "LOW": "blue"}.get(issue["severity"], "white")
            console.print(f"  [{sev_color}]{issue['severity']}[/{sev_color}]: {issue['resource']}")
            console.print(f"    {issue['message']}")
            if issue.get("before") and issue.get("after"):
                console.print(f"    [dim]{issue['attribute']}: {issue['before']} → {issue['after']}[/dim]")
            console.print()

    # Review changes
    if result["review_changes"]:
        console.print("[yellow]🟡 WORTH REVIEWING:[/yellow]")
        console.print()
        for change in result["review_changes"]:
            action_label = change.get("action", "unknown").upper()
            console.print(f"  [yellow]{action_label}[/yellow]: {change['address']}")
            for reason in change.get("reasons", []):
                console.print(f"    [dim]→ {reason}[/dim]")
        console.print()

    # Safe changes
    if result["safe_changes"]:
        console.print(f"[green]🟢 SAFE CHANGES ({len(result['safe_changes'])}):[/green]")
        for change in result["safe_changes"]:
            action_label = change.get("action", "unknown").upper()
            console.print(f"  [dim]{action_label}: {change['address']}[/dim]")
        console.print()

    # No dangerous changes = celebrate
    if not result["dangerous_changes"] and not result["security_issues"]:
        console.print("[bold green]✅ No dangerous changes detected. Plan looks safe![/bold green]")
        console.print()

    # Fail on threshold
    if fail_on:
        levels = {"critical": 0, "high": 1, "medium": 2, "low": 3}
        risk_levels_map = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "NONE": 4}
        threshold = levels[fail_on]
        current = risk_levels_map.get(risk_level, 4)
        if current <= threshold:
            console.print(f"[red]❌ Failing: Risk level {risk_level} meets --fail-on {fail_on} threshold[/red]")
            sys.exit(1)


# ============================================================
# COMMAND: forterra learn <path>
# Scans Terraform AND teaches you WHY each issue is a risk
# with real attack scenarios and breach references.
# ============================================================
@cli.command()
@click.argument("path", default=".", type=click.Path(exists=True))
@click.option("--rule", "-r", default=None, help="Show a specific rule by ID (e.g., FT-S3-001)")
@click.option("--list-rules", is_flag=True, help="List all available security rules with scenarios")
def learn(path, rule, list_rules):
    """Scan Terraform and learn WHY each issue is a security risk.

    Shows attack scenarios, real-world breaches, and fix code for every issue.

    Examples:
        forterra learn ./infrastructure/
        forterra learn --rule FT-S3-001
        forterra learn --list-rules
    """
    from forterra.learn import get_scenario, get_all_scenarios, format_breach
    from forterra.scanner import Scanner

    console.print()
    console.print(Panel(
        "[bold white]🏰 Forterra — Security Learning Mode[/bold white]\n"
        "[dim]Learn WHY each issue is dangerous with real attack scenarios[/dim]",
        border_style="cyan",
    ))
    console.print()

    # List all rules mode
    if list_rules:
        scenarios = get_all_scenarios()
        console.print(f"[bold]📚 {len(scenarios)} Security Lessons Available:[/bold]")
        console.print()
        for rule_id, scenario in scenarios.items():
            console.print(f"  [cyan]{rule_id}[/cyan] — {scenario['title']}")
            console.print(f"           [dim]{scenario['cis_benchmark']}[/dim]")
        console.print()
        console.print("[dim]Run [cyan]forterra learn --rule FT-S3-001[/cyan] to see a specific lesson.[/dim]")
        console.print("[dim]Run [cyan]forterra learn ./your-terraform/[/cyan] to scan and learn.[/dim]")
        return

    # Show a specific rule
    if rule:
        scenario = get_scenario(rule.upper())
        if not scenario:
            console.print(f"[red]❌ Unknown rule: {rule}[/red]")
            console.print("[dim]Run [cyan]forterra learn --list-rules[/cyan] to see all available rules.[/dim]")
            return
        _display_scenario(console, rule.upper(), scenario)
        return

    # Scan and learn mode — scan files, then teach about each issue found
    scanner = Scanner()
    tf_files = scanner.find_terraform_files(path)

    if not tf_files:
        console.print(f"[yellow]⚠️  No Terraform files found in {path}[/yellow]")
        console.print()
        console.print("[dim]You can still browse all lessons:[/dim]")
        console.print("  [cyan]forterra learn --list-rules[/cyan]")
        return

    console.print(f"[dim]Scanning {len(tf_files)} Terraform file(s)...[/dim]")
    console.print()

    issues = scanner.scan_files(tf_files)

    if not issues:
        console.print("[bold green]✅ No security issues found! Your Terraform looks secure.[/bold green]")
        console.print()
        console.print("[dim]Want to learn about common security mistakes anyway?[/dim]")
        console.print("  [cyan]forterra learn --list-rules[/cyan]")
        return

    console.print(f"[bold yellow]Found {len(issues)} issue(s). Let's learn about each one:[/bold yellow]")
    console.print()

    for i, issue in enumerate(issues):
        rule_id = issue.get("id", "")
        scenario = get_scenario(rule_id)

        # Always show the basic issue
        sev = issue["severity"]
        sev_color = {"CRITICAL": "red bold", "HIGH": "red", "MEDIUM": "yellow", "LOW": "blue"}.get(sev, "white")

        console.print(f"[{sev_color}]━━━ Issue {i+1}/{len(issues)}: {sev} ━━━[/{sev_color}]")
        console.print(f"[bold]{issue['resource']}[/bold] — {issue['message']}")

        if issue.get("file"):
            console.print(f"[dim]File: {issue['file']}[/dim]")

        if scenario:
            _display_scenario(console, rule_id, scenario)
        else:
            # No detailed scenario available — still show basic info
            console.print()
            if issue.get("fix_hint"):
                console.print(f"  [green]💡 Fix:[/green] {issue['fix_hint']}")
            console.print()

        console.print()

    console.print(f"[bold]📊 Summary: {len(issues)} issues found across {len(tf_files)} file(s)[/bold]")
    console.print("[dim]Fix these issues to improve your security posture and ace your Terraform cert! 💪[/dim]")
    console.print()


def _display_scenario(console, rule_id, scenario):
    """Display a full attack scenario with formatting."""
    console.print()

    # Attack Scenario
    console.print(f"  [red bold]🎯 ATTACK SCENARIO:[/red bold]")
    # Word wrap the scenario text
    _print_wrapped(console, scenario["attack_scenario"], indent=5)
    console.print()

    # Why it matters
    console.print(f"  [yellow bold]💡 WHY IT MATTERS:[/yellow bold]")
    _print_wrapped(console, scenario["why_it_matters"], indent=5)
    console.print()

    # Real breaches
    if scenario.get("real_breaches"):
        console.print(f"  [magenta bold]📰 REAL-WORLD BREACHES:[/magenta bold]")
        for breach in scenario["real_breaches"]:
            console.print(f"     [bold]{breach['company']}[/bold] ({breach['year']}) — [red]{breach['impact']}[/red]")
            console.print(f"     [dim]{breach['details']}[/dim]")
            console.print()

    # Fix code
    if scenario.get("fix_code"):
        console.print(f"  [green bold]🔧 HOW TO FIX:[/green bold]")
        console.print()
        fix_syntax = Syntax(scenario["fix_code"], "hcl", theme="monokai", line_numbers=False, padding=1)
        console.print(fix_syntax)
        console.print()

    # CIS Benchmark
    if scenario.get("cis_benchmark"):
        console.print(f"  [cyan]📚 {scenario['cis_benchmark']}[/cyan]")
        console.print()


def _print_wrapped(console, text, indent=0):
    """Print text with indentation, letting Rich handle wrapping."""
    prefix = " " * indent
    for line in text.split("\n"):
        console.print(f"{prefix}{line}")


# This is what runs when you type `forterra` in the terminal
if __name__ == "__main__":
    cli()
