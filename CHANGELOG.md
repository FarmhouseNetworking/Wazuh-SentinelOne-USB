# Changelog

## 1.0.0 - 2026-10-06

First release.

- `wazuh-s1-usb-install.sh`: one script with `install`, `status`, `selftest` and `uninstall` for the Wazuh manager. Pre-checks before any change, backup, validation with automatic rollback, and a 15-event self-test after the restart. `--usb-only` installs without SentinelOne.
- SentinelOne API collector (`sentinelone_pull.py`) for threats and activity, with rules 100600 to 100620.
- Windows USB rules 101500 to 101508, SentinelOne Device Control rules 101510 to 101515.
- Approved USB list with the `usb-approve` tool, which generates rules 101516 and 101517.
- Windows agent settings pushed through the shared `agent.conf`.
- `windows/New-UsbAuditingGpo.ps1` (Group Policy) and `windows/Set-UsbAuditing.ps1` (local) for the `HotPlugSecureOpen` registry value; `windows/Test-UsbAuditing.ps1` to check an endpoint.
- Test suite against a fake Wazuh tree.

Known gap: the installer has been run only against the test tree, not yet on a live manager. See "What has been tested" in the README.
