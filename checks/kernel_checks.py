"""
Kernel/network hardening checks, based on CIS Ubuntu Benchmark section 3.1 and 1.6.
Uses sysctl for both reading live values and applying persistent fixes.
"""
import os
from checks.base import BaseCheck, Status, Severity
from checks.utils import run, backup_file, read_file, write_file

SYSCTL_CONF = "/etc/sysctl.d/99-hardening.conf"


class IPForwardingDisabledCheck(BaseCheck):
    check_id = "CIS-3.1.1"
    title = "Ensure IP forwarding is disabled (net.ipv4.ip_forward)"
    severity = Severity.MEDIUM
    remediation_available = True

    def check(self):
        result = run(["sysctl", "net.ipv4.ip_forward"])
        value = result.stdout.strip().split("=")[-1].strip() if "=" in result.stdout else None
        if value == "0":
            return self._result(Status.PASS, current=value, expected="0")
        return self._result(Status.FAIL, current=value or "unknown", expected="0")

    def fix(self):
        run(["sudo", "sysctl", "-w", "net.ipv4.ip_forward=0"])
        self._persist("net.ipv4.ip_forward", "0")
        return True

    def _persist(self, key, value):
        if os.path.exists(SYSCTL_CONF):
            backup_file(SYSCTL_CONF)
            content = read_file(SYSCTL_CONF)
        else:
            content = "# Managed by linux-hardening-platform\n"
        if key in content:
            lines = [l for l in content.splitlines() if not l.strip().startswith(key)]
            content = "\n".join(lines) + "\n"
        content += f"{key} = {value}\n"
        with open("/tmp/_hardening_sysctl_tmp", "w") as f:
            f.write(content)
        run(["sudo", "cp", "/tmp/_hardening_sysctl_tmp", SYSCTL_CONF])


class ASLREnabledCheck(BaseCheck):
    check_id = "CIS-1.6.1"
    title = "Ensure Address Space Layout Randomization (ASLR) is enabled"
    severity = Severity.HIGH
    remediation_available = True

    def check(self):
        result = run(["sysctl", "kernel.randomize_va_space"])
        value = result.stdout.strip().split("=")[-1].strip() if "=" in result.stdout else None
        if value == "2":
            return self._result(Status.PASS, current=value, expected="2")
        return self._result(Status.FAIL, current=value or "unknown", expected="2")

    def fix(self):
        run(["sudo", "sysctl", "-w", "kernel.randomize_va_space=2"])
        ip_check = IPForwardingDisabledCheck()
        ip_check._persist("kernel.randomize_va_space", "2")
        return True


class ICMPRedirectsDisabledCheck(BaseCheck):
    check_id = "CIS-3.1.2"
    title = "Ensure ICMP redirects are not accepted (net.ipv4.conf.all.accept_redirects)"
    severity = Severity.MEDIUM
    remediation_available = True

    def check(self):
        result = run(["sysctl", "net.ipv4.conf.all.accept_redirects"])
        value = result.stdout.strip().split("=")[-1].strip() if "=" in result.stdout else None
        if value == "0":
            return self._result(Status.PASS, current=value, expected="0")
        return self._result(Status.FAIL, current=value or "unknown", expected="0")

    def fix(self):
        run(["sudo", "sysctl", "-w", "net.ipv4.conf.all.accept_redirects=0"])
        ip_check = IPForwardingDisabledCheck()
        ip_check._persist("net.ipv4.conf.all.accept_redirects", "0")
        return True


ALL_KERNEL_CHECKS = [
    IPForwardingDisabledCheck,
    ASLREnabledCheck,
    ICMPRedirectsDisabledCheck,
]
