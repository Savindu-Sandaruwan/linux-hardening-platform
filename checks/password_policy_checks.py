"""
Password policy checks, based on CIS Ubuntu Benchmark section 5.4.1.
Reads/writes /etc/login.defs.
"""
import re
import os
from checks.base import BaseCheck, Status, Severity
from checks.utils import backup_file, read_file, write_file

LOGIN_DEFS = "/etc/login.defs"


def _get_value(content: str, key: str):
    pattern = re.compile(rf"^\s*{key}\s+(\S+)", re.MULTILINE)
    match = pattern.search(content)
    return match.group(1) if match else None


def _set_value(content: str, key: str, value: str) -> str:
    pattern = re.compile(rf"^\s*{key}\s+\S+.*$", re.MULTILINE)
    if pattern.search(content):
        content = pattern.sub(f"{key}\t{value}", content)
    else:
        content += f"\n{key}\t{value}\n"
    return content


class PasswordMaxDaysCheck(BaseCheck):
    check_id = "CIS-5.4.1.1"
    title = "Ensure password expiration is 365 days or less (PASS_MAX_DAYS)"
    severity = Severity.MEDIUM
    remediation_available = True

    def check(self):
        if not os.path.exists(LOGIN_DEFS):
            return self._result(Status.ERROR, error="login.defs not found")
        content = read_file(LOGIN_DEFS)
        value = _get_value(content, "PASS_MAX_DAYS")
        if value and value.isdigit() and int(value) <= 365:
            return self._result(Status.PASS, current=value, expected="<=365")
        return self._result(Status.FAIL, current=value or "not set", expected="<=365")

    def fix(self):
        backup_file(LOGIN_DEFS)
        content = read_file(LOGIN_DEFS)
        content = _set_value(content, "PASS_MAX_DAYS", "365")
        write_file(LOGIN_DEFS, content)
        return True


class PasswordMinDaysCheck(BaseCheck):
    check_id = "CIS-5.4.1.2"
    title = "Ensure minimum password age is 1 day or more (PASS_MIN_DAYS)"
    severity = Severity.LOW
    remediation_available = True

    def check(self):
        if not os.path.exists(LOGIN_DEFS):
            return self._result(Status.ERROR, error="login.defs not found")
        content = read_file(LOGIN_DEFS)
        value = _get_value(content, "PASS_MIN_DAYS")
        if value and value.isdigit() and int(value) >= 1:
            return self._result(Status.PASS, current=value, expected=">=1")
        return self._result(Status.FAIL, current=value or "not set", expected=">=1")

    def fix(self):
        backup_file(LOGIN_DEFS)
        content = read_file(LOGIN_DEFS)
        content = _set_value(content, "PASS_MIN_DAYS", "1")
        write_file(LOGIN_DEFS, content)
        return True


class PasswordWarnAgeCheck(BaseCheck):
    check_id = "CIS-5.4.1.3"
    title = "Ensure password expiration warning is 7 days or more (PASS_WARN_AGE)"
    severity = Severity.LOW
    remediation_available = True

    def check(self):
        if not os.path.exists(LOGIN_DEFS):
            return self._result(Status.ERROR, error="login.defs not found")
        content = read_file(LOGIN_DEFS)
        value = _get_value(content, "PASS_WARN_AGE")
        if value and value.isdigit() and int(value) >= 7:
            return self._result(Status.PASS, current=value, expected=">=7")
        return self._result(Status.FAIL, current=value or "not set", expected=">=7")

    def fix(self):
        backup_file(LOGIN_DEFS)
        content = read_file(LOGIN_DEFS)
        content = _set_value(content, "PASS_WARN_AGE", "7")
        write_file(LOGIN_DEFS, content)
        return True


ALL_PASSWORD_POLICY_CHECKS = [
    PasswordMaxDaysCheck,
    PasswordMinDaysCheck,
    PasswordWarnAgeCheck,
]
