"""
SSH hardening checks, based on CIS Ubuntu Linux Benchmark section 5.2.
Reads /etc/ssh/sshd_config and checks/fixes key directives.
"""
import re
import os
from checks.base import BaseCheck, Status, Severity
from checks.utils import backup_file, read_file, write_file

SSHD_CONFIG = "/etc/ssh/sshd_config"


def _get_directive(content: str, key: str):
    """Find the effective value of an sshd_config directive (case-insensitive)."""
    pattern = re.compile(rf"^\s*{key}\s+(\S+)", re.IGNORECASE | re.MULTILINE)
    match = pattern.findall(content)
    return match[-1] if match else None


def _set_directive(content: str, key: str, value: str) -> str:
    """Set or append a directive in sshd_config content, commenting out old ones."""
    pattern = re.compile(rf"^\s*{key}\s+\S+.*$", re.IGNORECASE | re.MULTILINE)
    if pattern.search(content):
        content = pattern.sub(f"{key} {value}", content)
    else:
        content += f"\n{key} {value}\n"
    return content


class SSHRootLoginCheck(BaseCheck):
    check_id = "CIS-5.2.10"
    title = "Ensure SSH root login is disabled (PermitRootLogin no)"
    severity = Severity.HIGH
    remediation_available = True

    def check(self):
        if not os.path.exists(SSHD_CONFIG):
            return self._result(Status.ERROR, error="sshd_config not found")
        content = read_file(SSHD_CONFIG)
        value = _get_directive(content, "PermitRootLogin")
        if value and value.lower() == "no":
            return self._result(Status.PASS, current=value, expected="no")
        return self._result(Status.FAIL, current=value or "not set (defaults to yes)", expected="no")

    def fix(self):
        backup_file(SSHD_CONFIG)
        content = read_file(SSHD_CONFIG)
        content = _set_directive(content, "PermitRootLogin", "no")
        write_file(SSHD_CONFIG, content)
        return True


class SSHPasswordAuthCheck(BaseCheck):
    check_id = "CIS-5.2.11"
    title = "Ensure SSH password authentication is disabled (key-based only)"
    severity = Severity.HIGH
    remediation_available = True

    def check(self):
        if not os.path.exists(SSHD_CONFIG):
            return self._result(Status.ERROR, error="sshd_config not found")
        content = read_file(SSHD_CONFIG)
        value = _get_directive(content, "PasswordAuthentication")
        if value and value.lower() == "no":
            return self._result(Status.PASS, current=value, expected="no")
        return self._result(Status.FAIL, current=value or "not set (defaults to yes)", expected="no")

    def fix(self):
        # NOTE: this locks out password-based SSH logins. Only safe if key auth is already set up.
        backup_file(SSHD_CONFIG)
        content = read_file(SSHD_CONFIG)
        content = _set_directive(content, "PasswordAuthentication", "no")
        write_file(SSHD_CONFIG, content)
        return True


class SSHEmptyPasswordsCheck(BaseCheck):
    check_id = "CIS-5.2.12"
    title = "Ensure SSH PermitEmptyPasswords is disabled"
    severity = Severity.HIGH
    remediation_available = True

    def check(self):
        if not os.path.exists(SSHD_CONFIG):
            return self._result(Status.ERROR, error="sshd_config not found")
        content = read_file(SSHD_CONFIG)
        value = _get_directive(content, "PermitEmptyPasswords")
        if value and value.lower() == "no":
            return self._result(Status.PASS, current=value, expected="no")
        return self._result(Status.FAIL, current=value or "not set (defaults to no on most systems, verify)", expected="no")

    def fix(self):
        backup_file(SSHD_CONFIG)
        content = read_file(SSHD_CONFIG)
        content = _set_directive(content, "PermitEmptyPasswords", "no")
        write_file(SSHD_CONFIG, content)
        return True


class SSHMaxAuthTriesCheck(BaseCheck):
    check_id = "CIS-5.2.16"
    title = "Ensure SSH MaxAuthTries is set to 4 or less"
    severity = Severity.MEDIUM
    remediation_available = True

    def check(self):
        if not os.path.exists(SSHD_CONFIG):
            return self._result(Status.ERROR, error="sshd_config not found")
        content = read_file(SSHD_CONFIG)
        value = _get_directive(content, "MaxAuthTries")
        if value and value.isdigit() and int(value) <= 4:
            return self._result(Status.PASS, current=value, expected="<=4")
        return self._result(Status.FAIL, current=value or "not set (defaults to 6)", expected="<=4")

    def fix(self):
        backup_file(SSHD_CONFIG)
        content = read_file(SSHD_CONFIG)
        content = _set_directive(content, "MaxAuthTries", "4")
        write_file(SSHD_CONFIG, content)
        return True


ALL_SSH_CHECKS = [
    SSHRootLoginCheck,
    SSHPasswordAuthCheck,
    SSHEmptyPasswordsCheck,
    SSHMaxAuthTriesCheck,
]
