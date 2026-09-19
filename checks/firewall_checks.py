"""
Firewall checks, based on CIS Ubuntu Benchmark section 3.5 (ufw).
"""
from checks.base import BaseCheck, Status, Severity
from checks.utils import run


class UFWInstalledCheck(BaseCheck):
    check_id = "CIS-3.5.1"
    title = "Ensure ufw (firewall) is installed"
    severity = Severity.HIGH
    remediation_available = True

    def check(self):
        result = run(["dpkg", "-s", "ufw"])
        if result.returncode == 0:
            return self._result(Status.PASS, current="installed", expected="installed")
        return self._result(Status.FAIL, current="not installed", expected="installed")

    def fix(self):
        run(["sudo", "apt-get", "install", "-y", "ufw"], check=True)
        return True


class UFWActiveCheck(BaseCheck):
    check_id = "CIS-3.5.2"
    title = "Ensure ufw firewall is active and enabled"
    severity = Severity.HIGH
    remediation_available = True

    def check(self):
        result = run(["sudo", "ufw", "status"])
        active = "Status: active" in result.stdout
        if active:
            return self._result(Status.PASS, current="active", expected="active")
        return self._result(Status.FAIL, current="inactive", expected="active")

    def fix(self):
        # Allow SSH first so we don't lock ourselves out, then enable.
        run(["sudo", "ufw", "allow", "OpenSSH"])
        run(["sudo", "ufw", "--force", "enable"])
        return True


class UFWDefaultDenyIncomingCheck(BaseCheck):
    check_id = "CIS-3.5.3"
    title = "Ensure ufw default incoming policy is deny"
    severity = Severity.MEDIUM
    remediation_available = True

    def check(self):
        result = run(["sudo", "ufw", "status", "verbose"])
        if "Default: deny (incoming)" in result.stdout:
            return self._result(Status.PASS, current="deny", expected="deny")
        return self._result(Status.FAIL, current="not deny", expected="deny")

    def fix(self):
        run(["sudo", "ufw", "default", "deny", "incoming"])
        return True


ALL_FIREWALL_CHECKS = [
    UFWInstalledCheck,
    UFWActiveCheck,
    UFWDefaultDenyIncomingCheck,
]
