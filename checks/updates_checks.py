"""
Automatic updates check, based on CIS Ubuntu Benchmark section 1.2.
"""
import os
from checks.base import BaseCheck, Status, Severity
from checks.utils import run


class UnattendedUpgradesCheck(BaseCheck):
    check_id = "CIS-1.2.1"
    title = "Ensure unattended-upgrades (automatic security updates) is installed and enabled"
    severity = Severity.MEDIUM
    remediation_available = True

    def check(self):
        installed = run(["dpkg", "-s", "unattended-upgrades"]).returncode == 0
        enabled = False
        config_path = "/etc/apt/apt.conf.d/20auto-upgrades"
        if os.path.exists(config_path):
            with open(config_path) as f:
                content = f.read()
            enabled = '"1"' in content

        if installed and enabled:
            return self._result(Status.PASS, current="installed+enabled", expected="installed+enabled")
        return self._result(
            Status.FAIL,
            current=f"installed={installed}, enabled={enabled}",
            expected="installed+enabled",
        )

    def fix(self):
        run(["sudo", "apt-get", "install", "-y", "unattended-upgrades"], check=True)
        run(["sudo", "dpkg-reconfigure", "-f", "noninteractive", "unattended-upgrades"])
        return True


ALL_UPDATE_CHECKS = [
    UnattendedUpgradesCheck,
]
