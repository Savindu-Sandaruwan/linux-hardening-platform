#!/usr/bin/env python3
"""
Remote (agentless) scanner. SSHes into a remote Ubuntu host, copies just the
scanner code there temporarily, runs the audit, pulls the JSON report back,
then cleans up. No permanent agent/service is installed on the remote host.

Single-host usage:
    python3 scanner/remote_scan.py --host 18.232.136.69 --user ubuntu --key ~/Downloads/key.pem
    python3 scanner/remote_scan.py --host 18.232.136.69 --user ubuntu --key ~/Downloads/key.pem --fix

For scanning many hosts at once from a hosts.txt file, use scan_all.py instead,
which calls scan_one_host() from this file for each host.
"""
import argparse
import subprocess
import sys
import os
import json
import glob

PROJECT_ROOT = os.path.join(os.path.dirname(__file__), "..")
REMOTE_TMP_DIR = "/tmp/.linux_hardening_scan"


def _run(cmd, capture=True):
    return subprocess.run(cmd, capture_output=capture, text=True)


def _build_target(user, host):
    return f"{user}@{host}" if user else host


def scan_one_host(host, user, port="22", key=None, fix=False, quiet=False, timeout=25):
    """
    Runs the full remote scan workflow against one host.
    Returns a dict: {
        "host": str, "ok": bool, "error": str|None,
        "score": float|None, "passed": int|None, "failed": int|None,
        "report_path": str|None,
    }
    Never raises - all failures are captured in the returned dict so callers
    (like scan_all.py) can keep going after one host fails.
    """
    def log(msg):
        if not quiet:
            print(msg)

    target = _build_target(user, host)
    ssh_base = ["ssh", "-p", str(port), "-o", f"ConnectTimeout={timeout}", "-o", "BatchMode=yes"]
    scp_base = ["scp", "-P", str(port), "-r", "-o", f"ConnectTimeout={timeout}", "-o", "BatchMode=yes"]
    if key:
        key = os.path.expanduser(key)
        ssh_base += ["-i", key]
        scp_base += ["-i", key]

    result = {"host": host, "ok": False, "error": None, "score": None,
              "passed": None, "failed": None, "report_path": None}

    log(f"\n=== Scanning remote host: {host} ===")

    check = _run(ssh_base + [target, "python3 --version"])
    if check.returncode != 0:
        result["error"] = f"SSH/connectivity failed: {check.stderr.strip()[:200]}"
        log(f"ERROR: {result['error']}")
        return result
    log(f"Remote Python: {check.stdout.strip()}")

    prep = _run(ssh_base + [target, f"sudo rm -rf {REMOTE_TMP_DIR} && mkdir -p {REMOTE_TMP_DIR}"])
    if prep.returncode != 0:
        result["error"] = f"Could not prepare remote temp dir: {prep.stderr.strip()[:200]}"
        log(f"ERROR: {result['error']}")
        return result

    for folder in ("checks", "scanner"):
        local_path = os.path.join(PROJECT_ROOT, folder)
        copy = _run(scp_base + [local_path, f"{target}:{REMOTE_TMP_DIR}/"])
        if copy.returncode != 0:
            result["error"] = f"Failed copying {folder}/ to remote host: {copy.stderr.strip()[:200]}"
            log(f"ERROR: {result['error']}")
            return result
        log(f"Copied {folder}/ to remote host")

    remote_cmd = f"cd {REMOTE_TMP_DIR} && sudo -n python3 scanner/cli.py"
    if fix:
        remote_cmd += " --fix"
    log("Running audit on remote host...")
    scan = _run(ssh_base + [target, remote_cmd])
    if scan.returncode != 0 and "Score:" not in scan.stdout:
        result["error"] = f"Remote scan command failed: {scan.stderr.strip()[:300] or scan.stdout.strip()[:300]}"
        log(f"ERROR: {result['error']}")
        _run(ssh_base + [target, f"rm -rf {REMOTE_TMP_DIR}"])
        return result
    if not quiet:
        print(scan.stdout)

    local_reports_dir = os.path.join(PROJECT_ROOT, "reports")
    os.makedirs(local_reports_dir, exist_ok=True)
    before = set(glob.glob(os.path.join(local_reports_dir, "*.json")))
    pull = _run(scp_base + [f"{target}:{REMOTE_TMP_DIR}/reports/*.json", local_reports_dir])
    after = set(glob.glob(os.path.join(local_reports_dir, "*.json")))
    new_files = after - before

    _run(ssh_base + [target, f"sudo rm -rf {REMOTE_TMP_DIR}"])

    if pull.returncode != 0 or not new_files:
        result["error"] = "Scan ran but report could not be pulled back."
        log(f"ERROR: {result['error']}")
        return result

    report_path = sorted(new_files)[-1]
    try:
        with open(report_path) as f:
            data = json.load(f)
        result.update(ok=True, score=data["score"], passed=data["passed"],
                      failed=data["failed"], report_path=report_path)
    except Exception as e:
        result["error"] = f"Report pulled but could not be parsed: {e}"

    return result


def main():
    parser = argparse.ArgumentParser(description="Run the security audit on a remote host over SSH")
    parser.add_argument("--host", required=True, help="Remote hostname or IP")
    parser.add_argument("--user", required=True, help="SSH username")
    parser.add_argument("--port", default="22", help="SSH port (default 22)")
    parser.add_argument("--key", default=None, help="Path to SSH private key (optional)")
    parser.add_argument("--fix", action="store_true", help="Apply auto-remediation on the remote host")
    args = parser.parse_args()

    result = scan_one_host(args.host, args.user, args.port, args.key, args.fix)

    if result["ok"]:
        print(f"\nDone. Score: {result['score']}% ({result['passed']}/{result['passed']+result['failed']} passed)")
        print(f"Report saved locally at: {result['report_path']}")
    else:
        print(f"\nScan failed for {args.host}: {result['error']}")
        sys.exit(1)


if __name__ == "__main__":
    main()
