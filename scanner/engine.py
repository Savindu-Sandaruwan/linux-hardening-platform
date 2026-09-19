"""
Core scanning engine. Runs every registered check, optionally applies fixes,
and returns a structured report.
"""
import socket
import datetime
import json
import os
from dataclasses import asdict

from checks import ALL_CHECKS
from checks.base import Status


def run_scan(auto_fix: bool = False, dry_run: bool = True):
    """
    Run every check. If auto_fix=True and dry_run=False, apply fixes for
    every FAIL that has a remediation available.
    Returns a report dict.
    """
    results = []
    for check_cls in ALL_CHECKS:
        check = check_cls()
        result = check.check()

        if result.status == Status.FAIL and result.remediation_available and auto_fix:
            if dry_run:
                # Don't actually touch the system, just note that a fix would run.
                pass
            else:
                try:
                    success = check.fix()
                    if success:
                        # Re-check to confirm the fix actually worked.
                        result = check.check()
                        result.remediated = True
                except Exception as e:
                    result.error = f"Remediation failed: {e}"

        results.append(asdict(result))

    total = len(results)
    passed = sum(1 for r in results if r["status"] == "PASS")
    score = round((passed / total) * 100, 1) if total else 0.0

    report = {
        "hostname": socket.gethostname(),
        "timestamp": datetime.datetime.now().isoformat(),
        "score": score,
        "total_checks": total,
        "passed": passed,
        "failed": total - passed,
        "auto_fix_applied": auto_fix and not dry_run,
        "results": results,
    }
    return report


def save_report(report: dict) -> str:
    reports_dir = os.path.join(os.path.dirname(__file__), "..", "reports")
    os.makedirs(reports_dir, exist_ok=True)
    filename = f"report_{report['hostname']}_{report['timestamp'].replace(':', '-')}.json"
    path = os.path.join(reports_dir, filename)
    with open(path, "w") as f:
        json.dump(report, f, indent=2)
    return path
