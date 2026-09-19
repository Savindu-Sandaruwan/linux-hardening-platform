from checks.ssh_checks import ALL_SSH_CHECKS
from checks.firewall_checks import ALL_FIREWALL_CHECKS
from checks.filesystem_checks import ALL_FILESYSTEM_CHECKS
from checks.updates_checks import ALL_UPDATE_CHECKS
from checks.password_policy_checks import ALL_PASSWORD_POLICY_CHECKS
from checks.kernel_checks import ALL_KERNEL_CHECKS
from checks.audit_checks import ALL_AUDIT_CHECKS

# To add a new check: write it in the right file (or a new file), add its class
# to that file's ALL_*_CHECKS list, then add that list here.
ALL_CHECKS = (
    ALL_SSH_CHECKS
    + ALL_FIREWALL_CHECKS
    + ALL_FILESYSTEM_CHECKS
    + ALL_UPDATE_CHECKS
    + ALL_PASSWORD_POLICY_CHECKS
    + ALL_KERNEL_CHECKS
    + ALL_AUDIT_CHECKS
)
