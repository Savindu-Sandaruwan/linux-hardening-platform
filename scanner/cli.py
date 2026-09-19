#!/usr/bin/env python3
"""
CLI for the Linux Server Security Hardening & Audit Platform.

Usage:
    sudo python3 scanner/cli.py                 # audit only, no changes
    sudo python3 scanner/cli.py --fix --dry-run  # show what WOULD be fixed
    sudo python3 scanner/cli.py --fix            # actually apply fixes
"""
import argparse
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from rich.console import Console
from rich.table import Table
from scanner.engine import run_scan, save_report

console = Console()


def main():
    parser = argparse.ArgumentParser(description="Linux Security Hardening & Audit CLI")
    parser.add_argument("--fix", action="store_true", help="Attempt to auto-remediate FAIL findings")
    parser.add_argument("--dry-run", action="store_true", default=False,
                         help="With --fix, show what would change without applying it")
    args = parser.parse_args()

    if os.geteuid() != 0:
        console.print("[bold yellow]Warning:[/bold yellow] not running as root — many checks/fixes will fail or be inaccurate. Re-run with sudo.")

    dry_run = args.dry_run or not args.fix
    if args.fix and not args.dry_run:
        console.print("[bold red]Auto-remediation is ENABLED.[/bold red] Backups will be made to ./backups/ before any change.")

    console.print("[bold cyan]Running security audit...[/bold cyan]\n")
    report = run_scan(auto_fix=args.fix, dry_run=dry_run)

    table = Table(title=f"Audit Report — {report['hostname']}")
    table.add_column("Check ID")
    table.add_column("Title")
    table.add_column("Severity")
    table.add_column("Status")
    table.add_column("Current")
    table.add_column("Expected")

    for r in report["results"]:
        status_style = {
            "PASS": "[green]PASS[/green]",
            "FAIL": "[red]FAIL[/red]",
            "ERROR": "[yellow]ERROR[/yellow]",
            "SKIPPED": "[dim]SKIPPED[/dim]",
        }.get(r["status"], r["status"])
        note = " (fixed)" if r.get("remediated") else ""
        table.add_row(
            r["check_id"], r["title"], r["severity"],
            status_style + note, str(r["current_value"]), str(r["expected_value"]),
        )

    console.print(table)
    console.print(f"\n[bold]Score: {report['score']}%[/bold]  "
                   f"({report['passed']}/{report['total_checks']} passed)")

    path = save_report(report)
    console.print(f"\nReport saved to: [cyan]{path}[/cyan]")
    console.print("Upload this JSON file to the dashboard to view it visually.")


if __name__ == "__main__":
    main()
