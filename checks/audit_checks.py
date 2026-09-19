"""
Audit logging checks, based on CIS Ubuntu Benchmark section 4.1.
Checks that auditd (the Linux audit daemon) is installed and running.
"""
from checks.base import BaseCheck, Status, Severity
from checks.utils import run


class AuditdInstalledCheck(BaseCheck):
    check_id = "CIS-4.1.1.1"
    title = "Ensure auditd is installed"
    severity = Severity.MEDIUM
    remediation_available = True

    def check(self):
        result = run(["dpkg", "-s", "auditd"])
        if result.returncode == 0:
            return self._result(Status.PASS, current="installed", expected="installed")
        return self._result(Status.FAIL, current="not installed", expected="installed")

    def fix(self):
        run(["sudo", "apt-get", "install", "-y", "auditd", "audispd-plugins"], check=True)
        return True


class AuditdEnabledCheck(BaseCheck):
    check_id = "CIS-4.1.1.2"
    title = "Ensure auditd service is enabled and running"
    severity = Severity.MEDIUM
    remediation_available = True

    def check(self):
        result = run(["systemctl", "is-active", "auditd"])
        active = result.stdout.strip() == "active"
        enabled_result = run(["systemctl", "is-enabled", "auditd"])
        enabled = enabled_result.stdout.strip() == "enabled"
        if active and enabled:
            return self._result(Status.PASS, current="active+enabled", expected="active+enabled")
        return self._result(
            Status.FAIL,
            current=f"active={active}, enabled={enabled}",
            expected="active+enabled",
        )

    def fix(self):
        run(["sudo", "systemctl", "enable", "--now", "auditd"])
        return True


ALL_AUDIT_CHECKS = [
    AuditdInstalledCheck,
    AuditdEnabledCheck,
]
