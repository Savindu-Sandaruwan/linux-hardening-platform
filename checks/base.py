"""
Base class for all security checks.
Every check (SSH config, firewall, file permissions, etc.) inherits from this.
"""
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional


class Severity(str, Enum):
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"


class Status(str, Enum):
    PASS = "PASS"
    FAIL = "FAIL"
    ERROR = "ERROR"
    SKIPPED = "SKIPPED"


@dataclass
class CheckResult:
    check_id: str
    title: str
    severity: Severity
    status: Status
    current_value: str = ""
    expected_value: str = ""
    remediation_available: bool = False
    remediated: bool = False
    error: Optional[str] = None


class BaseCheck:
    """
    Subclass this for every new check.
    check_id: short unique id, e.g. "CIS-5.2.1"
    title: human readable description
    severity: HIGH / MEDIUM / LOW
    """
    check_id: str = "UNSET"
    title: str = "Unset check"
    severity: Severity = Severity.MEDIUM
    remediation_available: bool = False

    def check(self) -> CheckResult:
        """Must be implemented by subclass. Returns a CheckResult."""
        raise NotImplementedError

    def fix(self) -> bool:
        """
        Must be implemented if remediation_available = True.
        Should back up any file it touches before changing it.
        Returns True if fix succeeded.
        """
        raise NotImplementedError("This check has no auto-fix implemented.")

    def _result(self, status: Status, current="", expected="", error=None) -> CheckResult:
        return CheckResult(
            check_id=self.check_id,
            title=self.title,
            severity=self.severity,
            status=status,
            current_value=current,
            expected_value=expected,
            remediation_available=self.remediation_available,
            error=error,
        )
