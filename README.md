# Wazuh-SentinelOne-USB

Bring **SentinelOne** detections and console activity into a **self-hosted Wazuh manager**, and get a full audit trail of **USB storage** on Windows endpoints: what was blocked, which approved device was plugged in where, and which files were copied to it.

One script sets up the Wazuh side. Two small PowerShell scripts (one for Group Policy, one for a single computer) set the Windows registry value without which Windows silently logs nothing for USB drives.

```
 SentinelOne console  <--HTTPS, every 2 min--  sentinelone_pull.py  -->  sentinelone.json  -->  rules 100600-100620
 (threats, activity,     (outbound only, read-only token)                                       rules 101510-101515
  Device Control)

 Windows endpoint  --Wazuh agent-->  6416 device connected          -->  rules 101500-101508
 (audit policy +                     1006 disk attached                  rules 101516, 101517 (approved devices)
  HotPlugSecureOpen)                 4663/4656 file read/write/denied

 Approved USB list (etc/lists/approved_usb_serials)  <--  usb-approve SERIAL LABEL
```

SentinelOne does the blocking. Windows provides the record of what was allowed. The Approved USB list tells Wazuh which devices are expected, so everything else stands out.

| File | Purpose |
|---|---|
| `wazuh-s1-usb-install.sh` | Installer, status check, self-test and uninstaller for the Wazuh manager. Self-contained: copy this one file to the manager. |
| `windows/New-UsbAuditingGpo.ps1` | **Group Policy version.** Creates a GPO that sets the `HotPlugSecureOpen` registry value, and links it where you say. |
| `windows/Set-UsbAuditing.ps1` | **Local-only version.** Sets the same registry value on one computer (workgroup machines, a test machine, or an RMM script). Can also set the audit policy. |
| `windows/Test-UsbAuditing.ps1` | Checks a Windows computer: audit policy, registry value, Wazuh agent, serial numbers of connected USB disks, and an optional write test. |
| `docs/SETUP.md` | Step-by-step setup, from the SentinelOne service user to the first approved device |
| `docs/TROUBLESHOOTING.md` | Every problem hit while building this, with cause and fix |
| `payload/` | The files the installer writes: rules, the collector, `usb-approve`, agent settings |
| `src/`, `tools/build.py` | The installer template and the tool that builds the single-file installer from it |
| `tests/` | Test suite that runs the installer against a fake Wazuh tree, plus the sample events |

---

## What you get

| When this happens | Wazuh alert | Level |
|---|---|---|
| SentinelOne finds a malicious threat and has not mitigated it | 100602 | 12 |
| SentinelOne finds and mitigates a malicious threat (still open for review) | 100603 | 10 |
| A threat is closed in the console although the file was never removed | 100606 | 7 |
| A SentinelOne agent is uninstalled, decommissioned or disabled | 100611 | 12 |
| Someone adds or changes a SentinelOne exclusion | 100612 | 10 |
| The SentinelOne collection itself stops working (expired token, API error) | 100620 | 10 |
| SentinelOne blocks a USB device | 101510 | 10 |
| Someone adds, changes or deletes a Device Control rule | 101514 | 8 |
| Someone creates an **allow** rule for a device that is not on your Approved USB list | 101515 | 10 |
| An approved USB device is plugged in | 101516, 101517 | 3 |
| A USB storage device that is **not** approved connects | 101500, 101501 | 5 |
| A file is written to removable media (user and file name recorded) | 101505 | 7 |
| A file is written to a newly connected, non-approved USB device | 101507 | 10 |
| About 25 files are written to removable media within 5 minutes | 101508 | 12 |

The full list is in [Rule reference](#rule-reference).

---

## Requirements

- A Wazuh **manager**, version 4.3 or newer (built and run on 4.14), with root access
- For the SentinelOne part: outbound HTTPS from the manager to your SentinelOne console, and a SentinelOne **service user** with the read-only **Viewer** role
- For the USB part: Windows endpoints with the Wazuh agent
- Nothing inbound. No syslog listener and no firewall rule are added.

You can install the USB part without SentinelOne (`--usb-only`).

---

## Quick start

Full instructions, with what to expect at each step, are in **[docs/SETUP.md](docs/SETUP.md)**.

**1. SentinelOne console.** Create a service user with the Viewer role, scoped to your site. Copy its API token and note the site ID.

**2. Wazuh manager.**

```bash
curl -fsSLO https://raw.githubusercontent.com/FarmhouseNetworking/Wazuh-SentinelOne-USB/main/wazuh-s1-usb-install.sh
sudo bash wazuh-s1-usb-install.sh install
```

It asks for the console URL, the token (hidden) and the site ID, tests the token before changing anything, and finishes with a self-test.

**3. Windows endpoints.** Turn on the audit policy (Removable Storage: success and failure; Plug and Play: success), then deliver the registry value:

```powershell
# Domain: on a domain controller
.\New-UsbAuditingGpo.ps1 -ListTargets
.\New-UsbAuditingGpo.ps1 -LinkTarget 'OU=Workstations,DC=example,DC=local'

# One computer, or through your RMM
.\Set-UsbAuditing.ps1
```

**4. Check an endpoint.**

```powershell
.\Test-UsbAuditing.ps1 -WriteTest
```

**5. Approve a device.** Plug it in, read its serial number (from the SentinelOne block alert, or from `Test-UsbAuditing.ps1`), then on the manager:

```bash
sudo usb-approve 0123456789AB "Finance encrypted drive"
```

and create the matching allow rule in SentinelOne Device Control.

---

## What the installer does

1. Checks the server first: running as root, a Wazuh manager of a supported version, the rule IDs free, no earlier hand-made copy of the collector, and a clean `wazuh-analysisd -t`. **If any check fails it stops before changing anything.**
2. Tests the SentinelOne token against the two API endpoints it will use. The token goes to `curl` on standard input, so it never appears on a command line or in the process list.
3. Backs up everything it is about to touch to `/root/wazuh-s1-usb-backup-<timestamp>/`.
4. Writes the rules, the Approved USB list, `usb-approve`, the collector and its credentials file (root only, mode 600), and a logrotate entry.
5. Adds one marked block to `ossec.conf` (the collector and its log file) and registers the Approved USB list in the `<ruleset>` section.
6. Adds one marked block to the shared `agent.conf` of each agent group you name, so every Windows agent forwards the events the rules need. If a group already has its own Security channel block, that block is left alone and you are told.
7. Runs the collector once and shows what it pulled.
8. Runs `wazuh-analysisd -t`, `wazuh-logcollector -t` and `verify-agent-conf`. An error, or any **new** warning, triggers an automatic rollback.
9. Restarts `wazuh-manager`, then feeds 15 sample events through `wazuh-logtest` and checks each one lands on the expected rule. A miss triggers a rollback and a second restart.

You can run it again safely. A second run updates the files in place and keeps the saved credentials.

```
wazuh-s1-usb-install.sh install      [--s1-url URL] [--s1-site-id ID] [--s1-token-file FILE]
                                     [--usb-only] [--agent-group NAME]... [--no-agent-conf]
                                     [--no-restart] [-y]
wazuh-s1-usb-install.sh status
wazuh-s1-usb-install.sh selftest
wazuh-s1-usb-install.sh uninstall    [--no-restart] [-y]
```

For an unattended install, give the token in the `S1_API_TOKEN` environment variable or with `--s1-token-file`, and add `-y`.

---

## The Approved USB list

`/var/ossec/etc/lists/approved_usb_serials` holds one `serial:label` per line. `usb-approve` is the only thing that should edit it:

```bash
usb-approve SERIAL LABEL     # add a device, rebuild the rules, validate, restart the manager
usb-approve --remove SERIAL  # remove a device
usb-approve --list           # show the list
usb-approve --rebuild        # rebuild the rules from the list
```

It validates before restarting and puts the list back if validation fails.

Two things to know:

- **The list labels events; it does not allow anything.** Whatever blocks USB storage on your endpoints needs its own allow rule for the device. Add the device to the list first, then create the allow rule: that way the rule change alerts as an expected change (101514) and not as an allow rule for an unknown device (101515).
- **Use the serial number the device reports over USB**, exactly as shown in the block alert or by `Test-UsbAuditing.ps1`. It is not always the number printed on the case. A serial of all zeros, or one shared by several devices, cannot be approved safely: a rule for it would match every such device.

---

## Rule reference

| ID | Level | Fires when |
|---|---|---|
| 100600 | 0 | Any SentinelOne event (grouping rule) |
| 100601 | 5 | A threat record that fits none of the rules below |
| 100602 | 12 | Malicious, not mitigated, still open |
| 100603 | 10 | Malicious, mitigated, still open |
| 100604 | 8 | Suspicious, still open |
| 100605 | 3 | Threat resolved and mitigated (or marked benign) |
| 100606 | 7 | Threat resolved but never mitigated |
| 100610 | 3 | Any console or agent activity |
| 100611 | 12 | Agent uninstalled, decommissioned, disabled, or anti-tamper changed |
| 100612 | 10 | Exclusion created or changed |
| 100613 | 8 | Console sign-in failure |
| 100614 | 7 | Policy or blocklist change |
| 100620 | 10 | The collector failed |
| 101500 | 5 | Windows 6416: USB storage or a phone/camera connected |
| 101501 | 5 | Windows 1006: USB disk attached (vendor, model, serial, size) |
| 101502 | 10 | Windows 6423: device installation blocked by policy |
| 101503 | 10 | Windows 4656: access to removable storage denied |
| 101505 | 7 | Windows 4663: file written to removable storage |
| 101506 | 3 | Windows 4663: file read from removable storage |
| 101507 | 10 | File written to a USB device that connected in the last hour (not an approved one) |
| 101508 | 12 | About 25 writes to removable storage on one computer in 5 minutes |
| 101510 | 10 | SentinelOne Device Control blocked a device |
| 101511 | 5 | Any other SentinelOne Device Control device event |
| 101512 | 3 | SentinelOne reports a non-block event for an approved device |
| 101513 | 8 | SentinelOne blocked a device that is on the Approved USB list |
| 101514 | 8 | A Device Control rule was added, changed or deleted |
| 101515 | 10 | An allow rule was created for a serial that is not on the Approved USB list |
| 101516 | 3 | Windows 6416: an approved USB device connected |
| 101517 | 3 | Windows 1006: an approved USB disk attached |

Rules 100611 to 100614 match on the wording SentinelOne uses in its activity descriptions. Check them against your own console after a week or two and tighten them.

---

## What has been tested, and what has not

This was built on one live system: a Wazuh 4.14.8 manager, a SentinelOne site, and Windows 11 endpoints. The setup there was done by hand, one step at a time, and then packaged into this repository.

**Seen working on that live system**

- The collector, including its first-run backfill and its position tracking
- Rules that matched real events: 100602, 100605, 100610, 101500, 101501, 101505, 101510, 101513, 101514, 101516, 101517
- The pushed Security block replacing the agent's default one (confirmed by reading the agents' active configuration)
- The `HotPlugSecureOpen` value fixing "no file-access events for USB drives", both set by hand and delivered by a GPO built with the same commands `New-UsbAuditingGpo.ps1` runs

**Checked only with made-up events or stand-ins**

- **The installer itself has not yet been run on a live manager.** It passes its test suite (over 100 checks) against a fake Wazuh tree (`tests/run-tests.sh`), where Wazuh is replaced by a small emulator. That emulator checks rule load order, list registration and rule logic, but it is not Wazuh.
- Rules 100603, 100604, 100606, 100611 to 100614, 100620, 101502, 101503, 101506, 101507, 101508, 101512, 101515, and the phone/camera branch of 101500
- The three PowerShell scripts as scripts. Their logic was run with stand-ins for the registry, `auditpol` and the Group Policy commands; `-IncludeAuditPolicy` has not set a real audit policy yet.

Run the installer on a test manager first if you can, and please open an issue with what you find.

---

## Limitations

- **Rule IDs are fixed** (100600 to 100629 and 101500 to 101519). If they are taken on your manager the installer stops and says where.
- **SentinelOne does not report USB connections it allows**, only blocks. The record of an allowed connection comes from Windows.
- **The pushed Security block lets all 4663 events through**, not only removable-storage ones. If you also audit file access on ordinary disks, expect more events from those endpoints.
- **One file copy can produce two 4663 events**, so counts of "files written" run high.
- **Resolving a threat in the console re-sends its record**, so a bulk clean-up produces a burst of low-level alerts.
- The approved-device rule for 6416 is rebuilt from the list each time, because a Wazuh list can only match a whole field and the serial sits inside a longer device ID.

---

## Uninstall

```bash
sudo bash wazuh-s1-usb-install.sh uninstall
```

Removes everything the installer added, restores `ossec.conf` and each `agent.conf` to what they were without the marked blocks, and saves what it removed (including the Approved USB list) in a backup folder. Collected events in `/var/log/sentinelone/` are left in place.

On the Windows side, unlink or delete the GPO, and run `Set-UsbAuditing.ps1 -Undo` on computers where you want the registry value gone. In SentinelOne, delete the service user.

---

## Development

```bash
python3 tools/build.py          # rebuild wazuh-s1-usb-install.sh from src/ and payload/
sudo bash tests/run-tests.sh    # run the test suite
```

Edit `src/install.template.sh` and the files in `payload/`, never the built installer.

## License

MIT. See [LICENSE](LICENSE).
