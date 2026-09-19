#!/usr/bin/env python3
"""
Scan multiple remote hosts listed in a hosts.txt file, one after another,
and print a summary table at the end. No dashboard needed - everything
shows up right in the terminal.

hosts.txt format (comma-separated, one host per line, # for comments):
    # host,user,key_path,port(optional)
    18.232.136.69,ubuntu,~/Downloads/security-audit-key.pem
    192.168.1.50,ubuntu,~/.ssh/id_rsa,2222

Usage:
    python3 scanner/scan_all.py                      # uses hosts.txt in project root
    python3 scanner/scan_all.py --file my_hosts.txt
    python3 scanner/scan_all.py --fix                 # auto-remediate on every host
"""
import argparse
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from rich.console import Console
from rich.table import Table
from scanner.remote_scan import scan_one_host

console = Console()
DEFAULT_HOSTS_FILE = os.path.join(os.path.dirname(__file__), "..", "hosts.txt")


def load_hosts(path):
    hosts = []
    if not os.path.exists(path):
        console.print(f"[bold red]Hosts file not found:[/bold red] {path}")
        console.print("Create it with lines like: host,user,key_path")
        sys.exit(1)

    with open(path) as f:
        for line_num, raw_line in enumerate(f, start=1):
            line = raw_line.strip()
            if not line or line.startswith("#"):
                continue
            parts = [p.strip() for p in line.split(",")]
            if len(parts) < 2:
                console.print(f"[yellow]Skipping malformed line {line_num}: {line}[/yellow]")
                continue
            host, user = parts[0], parts[1]
            key = parts[2] if len(parts) > 2 and parts[2] else None
            port = parts[3] if len(parts) > 3 and parts[3] else "22"
            hosts.append({"host": host, "user": user, "key": key, "port": port})
    return hosts


def main():
    parser = argparse.ArgumentParser(description="Scan every host listed in a hosts.txt file")
    parser.add_argument("--file", default=DEFAULT_HOSTS_FILE, help="Path to hosts.txt (default: ./hosts.txt)")
    parser.add_argument("--fix", action="store_true", help="Apply auto-remediation on every host")
    parser.add_argument("--quiet", action="store_true", help="Suppress per-host scan output, show only the summary")
    args = parser.parse_args()

    hosts = load_hosts(args.file)
    if not hosts:
        console.print("[yellow]No hosts found in the hosts file.[/yellow]")
        sys.exit(0)

    console.print(f"[bold cyan]Scanning {len(hosts)} host(s) from {args.file}...[/bold cyan]")
    if args.fix:
        console.print("[bold red]Auto-remediation is ENABLED for all hosts.[/bold red]")

    results = []
    for h in hosts:
        r = scan_one_host(h["host"], h["user"], h["port"], h["key"], fix=args.fix, quiet=args.quiet)
        results.append(r)

    table = Table(title="Multi-Host Scan Summary")
    table.add_column("Host")
    table.add_column("Status")
    table.add_column("Score")
    table.add_column("Passed")
    table.add_column("Failed")
    table.add_column("Notes")

    ok_count = 0
    for r in results:
        if r["ok"]:
            ok_count += 1
            score = r["score"]
            score_style = "green" if score >= 80 else ("yellow" if score >= 50 else "red")
            table.add_row(
                r["host"], "[green]OK[/green]",
                f"[{score_style}]{score}%[/{score_style}]",
                str(r["passed"]), str(r["failed"]), "",
            )
        else:
            table.add_row(r["host"], "[red]FAILED[/red]", "-", "-", "-", (r["error"] or "")[:60])

    console.print("\n")
    console.print(table)
    console.print(f"\n[bold]{ok_count}/{len(hosts)} hosts scanned successfully.[/bold]")
    console.print("Individual JSON reports saved in ./reports/")


if __name__ == "__main__":
    main()
