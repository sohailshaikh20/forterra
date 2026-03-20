"""Forterra CLI — all terminal commands."""

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

from forterra import __version__
from forterra.ai_engine import AIEngine
from forterra.scanner import Scanner
from forterra.generator import Generator

console = Console()


@click.group()
@click.version_option(version=__version__, prog_name="forterra")
def cli():
    """🏰 Forterra — AI-powered Terraform plan analyzer & security trainer.

    Catch dangerous changes before they hit production.
    Learn why they're dangerous.
    """
    pass


@cli.command()
@click.argument("plan_file", required=False)
@click.option("--stdin", is_flag=True, help="Read plan JSON from stdin")
@click.option("--format", "-f", "output_format", default="pretty", type=click.Choice(["pretty", "json"]))
@click.option("--fail-on", type=click.Choice(["critical", "high", "medium", "low"]), default=None)
def analyze(plan_file, stdin, output_format, fail_on):
    """Analyze a Terraform plan for security risks and dangerous changes.

    \b
    Examples:
        terraform show -json tfplan > plan.json && forterra analyze plan.json
        terraform show -json tfplan | forterra analyze --stdin
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

    if stdin or (not plan_file and not sys.stdin.isatty()):
        plan_data = analyzer.load_plan_from_stdin()
        if not plan_data:
            console.print("[red]❌ Could not parse JSON from stdin.[/red]")
            sys.exit(1)
        result = analyzer.analyze_plan_data(plan_data)
    elif plan_file:
        result = analyzer.analyze_plan(plan_file)
    else:
        console.print("[red]❌ No plan file provided.[/red]")
        console.print()
        console.print("  [cyan]terraform show -json tfplan > plan.json[/cyan]")
        console.print("  [cyan]forterra analyze plan.json[/cyan]")
        sys.exit(1)

    if not result.get("success"):
        console.print(f"[red]❌ {result.get('error', 'Unknown error')}[/red]")
        sys.exit(1)

    if output_format == "json":
        console.print(json.dumps(result, indent=2, default=str))
        return

    risk_score = result["risk_score"]
    risk_level = result["risk_level"]
    summary = result["summary"]

    risk_color = {"CRITICAL": "red bold", "HIGH": "red", "MEDIUM": "yellow"}.get(risk_level, "green")

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

    if result["dangerous_changes"]:
        console.print("[red bold]🔴 DANGEROUS CHANGES — Review carefully:[/red bold]")
        console.print()
        for change in result["dangerous_changes"]:
            console.print(f"  [red bold]{change.get('action', '?').upper()}[/red bold]: [white]{change['address']}[/white]")
            for reason in change.get("reasons", []):
                console.print(f"    [red]→ {reason}[/red]")
            console.print()

    if result["security_issues"]:
        console.print("[red bold]🔒 SECURITY ISSUES DETECTED:[/red bold]")
        console.print()
        for issue in result["security_issues"]:
            sev_color = {"CRITICAL": "red bold", "HIGH": "red", "MEDIUM": "yellow"}.get(issue["severity"], "white")
            console.print(f"  [{sev_color}]{issue['severity']}[/{sev_color}]: {issue['resource']}")
            console.print(f"    {issue['message']}")
            if issue.get("before") and issue.get("after"):
                console.print(f"    [dim]{issue['attribute']}: {issue['before']} → {issue['after']}[/dim]")
            console.print()

    if result["review_changes"]:
        console.print("[yellow]🟡 WORTH REVIEWING:[/yellow]")
        console.print()
        for change in result["review_changes"]:
            console.print(f"  [yellow]{change.get('action', '?').upper()}[/yellow]: {change['address']}")
            for reason in change.get("reasons", []):
                console.print(f"    [dim]→ {reason}[/dim]")
        console.print()

    if result["safe_changes"]:
        console.print(f"[green]🟢 SAFE CHANGES ({len(result['safe_changes'])}):[/green]")
        for change in result["safe_changes"]:
            console.print(f"  [dim]{change.get('action', '?').upper()}: {change['address']}[/dim]")
        console.print()

    if not result["dangerous_changes"] and not result["security_issues"]:
        console.print("[bold green]✅ No dangerous changes detected. Plan looks safe![/bold green]")
        console.print()

    if fail_on:
        levels = {"critical": 0, "high": 1, "medium": 2, "low": 3}
        risk_map = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "NONE": 4}
        if risk_map.get(risk_level, 4) <= levels[fail_on]:
            console.print(f"[red]❌ Failing: risk level {risk_level} meets --fail-on {fail_on}[/red]")
            sys.exit(1)


@cli.command()
@click.argument("path", default=".", type=click.Path(exists=True))
@click.option("--rule", "-r", default=None, help="Show a specific rule (e.g., FT-S3-001)")
@click.option("--list-rules", is_flag=True, help="List all security lessons")
def learn(path, rule, list_rules):
    """Scan Terraform and learn WHY each issue is a security risk.

    \b
    Examples:
        forterra learn ./infrastructure/
        forterra learn --rule FT-S3-001
        forterra learn --list-rules
    """
    from forterra.learn import get_scenario, get_all_scenarios

    console.print()
    console.print(Panel(
        "[bold white]🏰 Forterra — Security Learning Mode[/bold white]\n"
        "[dim]Learn WHY each issue is dangerous with real attack scenarios[/dim]",
        border_style="cyan",
    ))
    console.print()

    if list_rules:
        scenarios = get_all_scenarios()
        console.print(f"[bold]📚 {len(scenarios)} Security Lessons Available:[/bold]")
        console.print()
        for rule_id, scenario in scenarios.items():
            console.print(f"  [cyan]{rule_id}[/cyan] — {scenario['title']}")
            console.print(f"           [dim]{scenario['cis_benchmark']}[/dim]")
        console.print()
        console.print("[dim]Run [cyan]forterra learn --rule FT-S3-001[/cyan] for a specific lesson.[/dim]")
        return

    if rule:
        scenario = get_scenario(rule.upper())
        if not scenario:
            console.print(f"[red]❌ Unknown rule: {rule}[/red]")
            return
        _display_scenario(rule.upper(), scenario)
        return

    scanner = Scanner()
    tf_files = scanner.find_terraform_files(path)

    if not tf_files:
        console.print(f"[yellow]⚠️  No Terraform files found in {path}[/yellow]")
        console.print("  [cyan]forterra learn --list-rules[/cyan]")
        return

    console.print(f"[dim]Scanning {len(tf_files)} Terraform file(s)...[/dim]")
    console.print()

    issues = scanner.scan_files(tf_files)

    if not issues:
        console.print("[bold green]✅ No security issues found![/bold green]")
        return

    console.print(f"[bold yellow]Found {len(issues)} issue(s). Let's learn about each one:[/bold yellow]")
    console.print()

    for i, issue in enumerate(issues):
        sev = issue["severity"]
        sev_color = {"CRITICAL": "red bold", "HIGH": "red", "MEDIUM": "yellow", "LOW": "blue"}.get(sev, "white")

        console.print(f"[{sev_color}]━━━ Issue {i+1}/{len(issues)}: {sev} ━━━[/{sev_color}]")
        console.print(f"[bold]{issue['resource']}[/bold] — {issue['message']}")
        if issue.get("file"):
            console.print(f"[dim]File: {issue['file']}[/dim]")

        scenario = get_scenario(issue.get("id", ""))
        if scenario:
            _display_scenario(issue["id"], scenario)
        elif issue.get("fix_hint"):
            console.print(f"\n  [green]💡 Fix:[/green] {issue['fix_hint']}\n")

        console.print()

    console.print(f"[bold]📊 Summary: {len(issues)} issues found across {len(tf_files)} file(s)[/bold]")
    console.print("[dim]Fix these issues to improve your security posture and ace your Terraform cert! 💪[/dim]")
    console.print()


def _display_scenario(rule_id, scenario):
    console.print()
    console.print(f"  [red bold]🎯 ATTACK SCENARIO:[/red bold]")
    console.print(f"     {scenario['attack_scenario']}")
    console.print()
    console.print(f"  [yellow bold]💡 WHY IT MATTERS:[/yellow bold]")
    console.print(f"     {scenario['why_it_matters']}")
    console.print()

    if scenario.get("real_breaches"):
        console.print(f"  [magenta bold]📰 REAL-WORLD BREACHES:[/magenta bold]")
        for breach in scenario["real_breaches"]:
            console.print(f"     [bold]{breach['company']}[/bold] ({breach['year']}) — [red]{breach['impact']}[/red]")
            console.print(f"     [dim]{breach['details']}[/dim]")
            console.print()

    if scenario.get("fix_code"):
        console.print(f"  [green bold]🔧 HOW TO FIX:[/green bold]")
        console.print()
        console.print(Syntax(scenario["fix_code"], "hcl", theme="monokai", line_numbers=False, padding=1))
        console.print()

    if scenario.get("cis_benchmark"):
        console.print(f"  [cyan]📚 {scenario['cis_benchmark']}[/cyan]")
        console.print()


@cli.command()
@click.argument("path", default=".", type=click.Path(exists=True))
@click.option("--format", "-f", "output_format", default="pretty", type=click.Choice(["pretty", "json", "sarif"]))
@click.option("--fail-on", type=click.Choice(["critical", "high", "medium", "low"]), default=None)
def scan(path, output_format, fail_on):
    """Scan existing Terraform files for security issues.

    \b
    Examples:
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

    issues = scanner.scan_files(tf_files)

    if not issues:
        console.print("[bold green]✅ No security issues found![/bold green]")
        return

    severity_colors = {"CRITICAL": "red bold", "HIGH": "red", "MEDIUM": "yellow", "LOW": "blue"}
    severity_order = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]
    issues_sorted = sorted(issues, key=lambda x: severity_order.index(x.get("severity", "LOW")))

    console.print(f"[bold yellow]⚠️  Found {len(issues)} issue(s):[/bold yellow]")
    console.print()

    for issue in issues_sorted:
        color = severity_colors.get(issue["severity"], "white")
        console.print(f"  [{color}]{issue['severity']}[/{color}]: {issue['resource']} — {issue['message']}")
        if issue.get("fix_hint"):
            console.print(f"          [dim]💡 {issue['fix_hint']}[/dim]")

    console.print()
    console.print("[dim]Run [cyan]forterra fix[/cyan] to auto-remediate with AI.[/dim]")
    console.print()

    if fail_on:
        severity_levels = {"critical": 0, "high": 1, "medium": 2, "low": 3}
        threshold = severity_levels[fail_on]
        for issue in issues:
            if severity_levels.get(issue["severity"].lower(), 3) <= threshold:
                sys.exit(1)


@cli.command()
@click.argument("path", default=".", type=click.Path(exists=True))
def score(path):
    """Get a security score for your Terraform infrastructure."""
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

    deductions = sum({"CRITICAL": 20, "HIGH": 10, "MEDIUM": 5, "LOW": 2}.get(i["severity"], 0) for i in issues)
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


@cli.command()
@click.argument("prompt")
@click.option("--output", "-o", default="./forterra-output")
@click.option("--provider", "-p", default="aws", type=click.Choice(["aws", "azure", "gcp"]))
@click.option("--compliance", "-c", multiple=True)
@click.option("--dry-run", is_flag=True)
def generate(prompt, output, provider, compliance, dry_run):
    """Generate secure Terraform from a plain English description. (Requires API key)"""
    ai = AIEngine()
    if not ai.has_api_key():
        console.print("[red]❌ No API key found. Set FORTERRA_API_KEY environment variable.[/red]")
        sys.exit(1)

    console.print(f'\n[bold]🏰 Generating secure Terraform for:[/bold] [cyan]"{prompt}"[/cyan]\n')

    with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}"), console=console) as progress:
        progress.add_task("🔍 Analyzing architecture requirements...", total=None)
        result = ai.generate_infrastructure(prompt, provider, list(compliance))

    if not result.get("success"):
        console.print(f"[red]❌ {result.get('error', 'Unknown error')}[/red]")
        sys.exit(1)

    score = result.get("security_score", 0)
    console.print(f"[green]✅ Security Score: {score}/100 ({result.get('score_grade', '?')})[/green]")

    if dry_run:
        for filename, content in result.get("files", {}).items():
            console.print(f"\n[bold cyan]📄 {filename}[/bold cyan]")
            console.print(Syntax(content, "hcl", theme="monokai", line_numbers=True))
    else:
        generator = Generator()
        written = generator.write_files(Path(output), result.get("files", {}))
        console.print(f"\n[green]✅ Generated {len(written)} files in {output}/[/green]")
        for f in written:
            console.print(f"   [dim]├── {f}[/dim]")
    console.print()


@cli.command()
@click.argument("path", default=".", type=click.Path(exists=True))
@click.option("--auto-pr", is_flag=True)
@click.option("--interactive", "-i", is_flag=True)
def fix(path, auto_pr, interactive):
    """Auto-fix security issues with AI-powered remediation. (Requires API key)"""
    scanner = Scanner()
    tf_files = scanner.find_terraform_files(path)
    issues = scanner.scan_files(tf_files)

    if not issues:
        console.print("[bold green]✅ No issues to fix![/bold green]")
        return

    ai = AIEngine()
    if not ai.has_api_key():
        console.print("[red]❌ API key required. Set FORTERRA_API_KEY.[/red]")
        sys.exit(1)

    console.print(f"[yellow]Found {len(issues)} issue(s) to fix.[/yellow]\n")

    for issue in issues:
        console.print(f"  [bold]{issue['severity']}[/bold]: {issue['resource']} — {issue['message']}")
        if interactive and not click.confirm("    Apply fix?", default=True):
            continue

        with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}"), console=console) as prog:
            prog.add_task("    Generating fix...", total=None)
            fix_result = ai.generate_fix(issue)

        if fix_result.get("success"):
            console.print(f"    [green]✓ Fixed: {fix_result.get('description', 'Applied fix')}[/green]")
        else:
            console.print(f"    [red]✗ Could not auto-fix: {fix_result.get('error', 'Unknown')}[/red]")
        console.print()


@cli.command()
def init():
    """Initialize Forterra in your project — creates .forterra.yml config."""
    config_path = Path(".forterra.yml")
    if config_path.exists():
        console.print("[yellow]⚠️  .forterra.yml already exists.[/yellow]")
        return

    config_path.write_text("""# Forterra Configuration
provider: aws
compliance:
  - cis
scan:
  min_severity: medium
  fail_on: high
generate:
  output_dir: ./infrastructure
  include_comments: true
""")
    console.print("[green]✅ Created .forterra.yml[/green]")


if __name__ == "__main__":
    cli()
