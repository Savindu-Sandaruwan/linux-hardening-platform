"""
File permission checks, based on CIS Ubuntu Benchmark section 6.1.
Checks permissions on sensitive files like /etc/shadow, /etc/passwd.
"""
import os
import stat
from checks.base import BaseCheck, Status, Severity
from checks.utils import run


class ShadowPermissionsCheck(BaseCheck):
    check_id = "CIS-6.1.3"
    title = "Ensure /etc/shadow permissions are 640 or more restrictive"
    severity = Severity.HIGH
    remediation_available = True
    _path = "/etc/shadow"

    def check(self):
        if not os.path.exists(self._path):
            return self._result(Status.ERROR, error="file not found")
        mode = oct(stat.S_IMODE(os.stat(self._path).st_mode))
        current = mode[-3:]
        if int(current) <= 640:
            return self._result(Status.PASS, current=current, expected="<=640")
        return self._result(Status.FAIL, current=current, expected="<=640")

    def fix(self):
        run(["sudo", "chmod", "640", self._path])
        return True


class PasswdPermissionsCheck(BaseCheck):
    check_id = "CIS-6.1.2"
    title = "Ensure /etc/passwd permissions are 644 or more restrictive"
    severity = Severity.MEDIUM
    remediation_available = True
    _path = "/etc/passwd"

    def check(self):
        if not os.path.exists(self._path):
            return self._result(Status.ERROR, error="file not found")
        mode = oct(stat.S_IMODE(os.stat(self._path).st_mode))
        current = mode[-3:]
        if int(current) <= 644:
            return self._result(Status.PASS, current=current, expected="<=644")
        return self._result(Status.FAIL, current=current, expected="<=644")

    def fix(self):
        run(["sudo", "chmod", "644", self._path])
        return True


class NoEmptyPasswordAccountsCheck(BaseCheck):
    check_id = "CIS-6.2.1"
    title = "Ensure no accounts have empty passwords"
    severity = Severity.HIGH
    remediation_available = False  # too dangerous to auto-fix (would lock/guess passwords)

    def check(self):
        result = run(["sudo", "awk", "-F:", '($2 == "") {print $1}', "/etc/shadow"])
        empty_accounts = [a for a in result.stdout.splitlines() if a.strip()]
        if not empty_accounts:
            return self._result(Status.PASS, current="none", expected="none")
        return self._result(Status.FAIL, current=", ".join(empty_accounts), expected="none")


ALL_FILESYSTEM_CHECKS = [
    ShadowPermissionsCheck,
    PasswdPermissionsCheck,
    NoEmptyPasswordAccountsCheck,
]
