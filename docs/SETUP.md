# Setup, step by step

This takes about an hour the first time. Each step says where it runs and what you should see.

| Step | Where | What |
|---|---|---|
| 1 | SentinelOne console | Create a read-only service user |
| 2 | Wazuh manager | Run the installer |
| 3 | Wazuh manager and dashboard | Check that events arrive |
| 4 | Wazuh manager | Confirm the Windows agents picked up their settings |
| 5 | Domain controller or each endpoint | Audit policy and the `HotPlugSecureOpen` registry value |
| 6 | SentinelOne console | Block USB storage (if you do not already) |
| 7 | Endpoint, manager, console | Approve a device |
| 8 | All three | Test the whole chain |

Installing without SentinelOne? Skip steps 1, 3 and 6 and add `--usb-only` in step 2.

---

## 1. Create a SentinelOne service user

**Where:** SentinelOne management console.

1. Open **Settings > Users > Service Users** (in newer consoles: **Policy & Settings > User Management > Service Users**).
2. Choose **Actions > Create New Service User**.
3. Give it a name that says what it is for, such as `wazuh-pull`.
4. Set the **scope to the one site** you want to collect from, and the **role to Viewer**. Viewer is read-only, which is all the collector needs.
5. Pick an expiry date and create the user.
6. **Copy the API token now.** The console shows it once. Copy the whole string: tokens are long (often several hundred characters), and a cut-off token is the most common cause of a failed install.
7. Note the **site ID** (shown on the site's information page; it is a long number) and your console URL, for example `https://usea1-xxxx.sentinelone.net`.

Put the token's expiry date in your calendar or ticket system. When it expires the collection stops and Wazuh raises alert 100620.

---

## 2. Run the installer

**Where:** the Wazuh manager, as root.

Get the script onto the manager. Either:

```bash
curl -fsSLO https://raw.githubusercontent.com/FarmhouseNetworking/Wazuh-SentinelOne-USB/main/wazuh-s1-usb-install.sh
```

or copy the single file `wazuh-s1-usb-install.sh` there by any means. It needs nothing else from this repository.

Then:

```bash
sudo bash wazuh-s1-usb-install.sh install
```

It asks three questions:

```
SentinelOne console URL (e.g. https://usea1-xxxx.sentinelone.net):
SentinelOne API token (input is hidden):
Site ID to collect from (blank = everything the token can see):
```

and then shows what it is about to do and asks you to confirm.

**What you should see**

```
Wazuh manager 4.14.8
Token length: 437 characters
SentinelOne API: threats OK
SentinelOne API: activities OK
Backup: /root/wazuh-s1-usb-backup-20260101-120000
Running the collector once (first run looks back 24 hours)...
Events collected so far, by type:
     40 "s1_type":"activity"
Validating the configuration...
Configuration is valid.
wazuh-manager restarted.
Self-test: 15 of 15 sample events hit the expected rule.

Installed (version 1.0.0). Backup of the previous state: /root/wazuh-s1-usb-backup-...
```

**If it stops** it prints `STOP:` and a reason, followed by `Nothing was changed.` when that is true. The common ones:

| Message | Meaning |
|---|---|
| `SentinelOne rejected the token (HTTP 401)` | The token is wrong, cut short, expired, or from another console. Generate a new one and copy all of it. |
| `not allowed to read ... (HTTP 403)` | The token is fine but the service user's role or scope does not cover that site. |
| `could not reach ...` | Wrong URL, or outbound HTTPS from the manager is blocked. |
| `rule IDs this script uses ... already appear` | See TROUBLESHOOTING.md, "Rule IDs already in use". |

If something fails **after** changes began, the installer rolls everything back by itself and says so.

### Unattended install

```bash
export S1_API_TOKEN='...'          # or: --s1-token-file /root/s1.token
sudo -E bash wazuh-s1-usb-install.sh install \
     --s1-url https://usea1-xxxx.sentinelone.net --s1-site-id 1234567890123456789 -y
```

The token is never accepted as a command-line option, because command lines are visible to other users and end up in shell history.

### Options you may need

| Option | Use it when |
|---|---|
| `--usb-only` | You do not use SentinelOne, or want only the Windows USB rules and the approved list |
| `--agent-group NAME` | Your Windows agents are in a group other than `default`. Repeat it for several groups. |
| `--no-agent-conf` | You manage `agent.conf` yourself. Then add the two blocks from `payload/agent-*.xml` by hand. |
| `--no-restart` | You want to restart `wazuh-manager` yourself, later. Run `selftest` afterwards. |

---

## 3. Check that events arrive

**Where:** the manager.

```bash
sudo bash wazuh-s1-usb-install.sh status
```

shows what is installed, the collector's position, a count of collected events by type, and today's alerts from these rules.

**In the Wazuh dashboard**, filter on `rule.groups: sentinelone`. Console and agent activity appears as rule 100610 at level 3. On a quiet site that may be only the routine "Live Updates ... were merged" records, which is enough to prove the pipeline.

To test with a detection, see step 8.

---

## 4. Confirm the Windows agents picked up their settings

The installer adds a block to the shared `agent.conf` of the agent group. Every agent in that group fetches it by itself, usually within a few minutes. The block does two things:

- replaces the agent's built-in Security channel filter with one that no longer throws away event 4663 (file access), and keeps event 4656 for removable storage;
- collects the `Microsoft-Windows-Partition/Diagnostic` channel, event 1006.

To see the filter an agent is **actually using**, run this on the manager (replace `001` with an agent ID from `/var/ossec/bin/agent_control -l`):

```bash
sudo /var/ossec/framework/python/bin/python3 - <<'EOF'
import json
from wazuh.core.configuration import get_active_configuration
cfg = get_active_configuration(agent_id='001', component='logcollector', configuration='localfile')
for x in cfg.get('localfile', []):
    if 'Security' in json.dumps(x):
        q = x.get('query', x)
        if isinstance(q, dict):
            q = q.get('value', q)
        print(' '.join(str(q).split()))
EOF
```

You want the query that ends with `or (EventID = 4656 and Task = 12812)]`. If you see `EventID != 4663` in it, the agent is still on its default filter.

**If the installer said a group "already had its own Security channel block"**, it left that block alone. Open that group's `agent.conf` and make sure its query does not exclude 4663, and lets 4656 through for task 12812. `payload/agent-security.xml` shows a query that does both.

---

## 5. Windows endpoints: audit policy and registry value

Three settings are needed on every endpoint. The first two are audit policy; the third is the one people miss.

| Setting | Value | Produces |
|---|---|---|
| Audit **Removable Storage** | Success and Failure | Events 4663 and 4656: files read, written, or denied on removable media |
| Audit **Plug and Play Events** (called "Audit PNP Activity" in Group Policy) | Success | Event 6416: a device was connected |
| Registry `HKLM\SYSTEM\CurrentControlSet\Control\Storage\HotPlugSecureOpen` | `1` (DWORD) | Makes the first setting actually work for hot-plugged USB drives |

Without `HotPlugSecureOpen`, some Windows builds log **nothing** for files on a USB drive even though the audit policy shows as enabled. Microsoft documents this for "some versions of Windows 10". It was also needed on Windows 11 build 26200, where a USB DVD drive was audited without it and USB flash drives were not.

Nothing needs to be set on the drives themselves. This auditing is switched on at the computer and covers every file on any removable drive, whatever its file system.

### 5a. Domain: Group Policy

**Audit policy.** In Group Policy Management, edit a GPO that applies to your workstations:

`Computer Configuration > Policies > Windows Settings > Security Settings > Advanced Audit Policy Configuration > Audit Policies`

- `Object Access > Audit Removable Storage`: tick **Success** and **Failure**
- `Detailed Tracking > Audit PNP Activity`: tick **Success**

**Registry value.** On a domain controller, or a computer with the Group Policy Management tools, in PowerShell as a domain administrator:

```powershell
# 1. Create the GPO. It is not linked yet, so nothing changes on any computer.
.\New-UsbAuditingGpo.ps1

# 2. See which containers hold your computer accounts.
.\New-UsbAuditingGpo.ps1 -ListTargets

# 3. Link it to the OU that holds the workstations.
.\New-UsbAuditingGpo.ps1 -LinkTarget 'OU=Workstations,DC=example,DC=local'
```

Link it to the same place as the GPO that carries the audit policy, so the two always apply together. Keep it off servers and domain controllers unless you want USB file auditing there too.

The script is safe to run again: it reuses the GPO and does not add a second link.

Computers apply the policy within about two hours or at restart. To apply it at once on one computer: `gpupdate /target:computer /force`.

### 5b. One computer, a workgroup, or an RMM tool

In PowerShell as administrator (or as SYSTEM from your RMM):

```powershell
# Registry value only. Use this on domain computers whose audit policy comes from a GPO.
.\Set-UsbAuditing.ps1

# Registry value and audit policy. Use this on workgroup computers.
.\Set-UsbAuditing.ps1 -IncludeAuditPolicy
```

On a domain computer do not rely on `-IncludeAuditPolicy`: the domain's audit policy overwrites a local one at the next refresh.

To undo: `.\Set-UsbAuditing.ps1 -Undo` (add `-IncludeAuditPolicy` to turn the two audit settings off as well).

### 5c. Check an endpoint

```powershell
.\Test-UsbAuditing.ps1
```

```
Audit policy
  OK     Removable Storage: Success and Failure (needs Success and Failure)
  OK     Plug and Play Events: Success (needs Success)

Registry
  OK     HotPlugSecureOpen = 1

Wazuh agent
  OK     Wazuh agent service is running

USB disks connected now
  Vendor Secure Drive  serial: 0123456789AB  size: 3.8 GB  drive: D

No problems found.
```

With a USB drive plugged in (and unlocked, if it is an encrypted one), add `-WriteTest`. The script writes a small text file to the drive, counts the file-access events Windows logged, and deletes the file:

```
  OK     drive D: wrote a test file, Windows logged 2 file-access event(s)
```

**Zero events?** Unplug the drive and plug it back in. A drive that was already connected when the registry value arrived is not audited until it is reconnected. No restart was needed in testing.

---

## 6. Block USB storage in SentinelOne

If you do not block USB storage yet: in the SentinelOne console, under **Device Control** for your site, create a rule that **blocks USB devices of class 08 (Mass Storage)**. From then on every USB storage device is blocked unless a rule above it allows that device.

Blocks then appear in Wazuh as rule 101510, naming the device, the computer, the signed-in user and the rule that blocked it. If they do not, check in the site's policy that Device Control events are reported to the activity log.

This step is optional as far as Wazuh is concerned: the Windows rules and the Approved USB list work with any USB control, or with none.

---

## 7. Approve a device

Do it in this order. Listing the device before allowing it means the change is recorded as an expected one.

1. **Plug the device into an endpoint** and unlock it if it is an encrypted drive. Many hardware-encrypted drives do not appear to the computer at all until they are unlocked. SentinelOne blocks it.
2. **Read the serial number** the device reported:
   - in the Wazuh alert for rule 101510 (field `data.s1.data.uid`), or
   - on the endpoint with `.\Test-UsbAuditing.ps1`, if the device is not blocked there.
3. **Check the serial is usable.** It must be unique to that device. A serial of all zeros (some USB-to-SATA adapters report one) or one shared by a batch of cheap drives cannot be approved safely.
4. **Add it to the Approved USB list**, on the manager:

   ```bash
   sudo usb-approve 0123456789AB "Finance encrypted drive"
   ```

   This restarts `wazuh-manager`.
5. **Create the allow rule in SentinelOne.** Device Control > new rule > interface USB > rule type **Serial ID** > the serial number > class **08 Mass Storage** > action **Allow Read & Write**. Make sure it sits above the block rule if your console shows an order.
6. **Plug the device in again.** It should mount. Within a minute Wazuh should show rule 101516 (and 101517 if it is a disk).

To retire a device: delete its allow rule in SentinelOne, then `sudo usb-approve --remove SERIAL`.

Keep your own register of approved devices as well: who holds each one, who approved it and when. Wazuh's list records serial numbers and labels only.

---

## 8. Test the whole chain

| Do this | Expect in Wazuh |
|---|---|
| Plug in a USB drive that is not approved | 101510 (level 10): blocked, with device, computer and user |
| Create an allow rule in SentinelOne for a serial that is on the list | 101514 (level 8) |
| Create an allow rule for a serial that is **not** on the list, then delete it | 101515 (level 10), then 101514 |
| Plug in an approved drive | 101516 and 101517 (level 3) |
| Copy a file onto the approved drive | 101505 (level 7), naming the user and the file. No 101507. |
| Create the EICAR test file on an endpoint (below) | 100602 (level 12) or 100603 (level 10), depending on whether SentinelOne mitigated it |
| Mark that threat resolved in the console | 100605 (level 3), or 100606 (level 7) if the file was never removed |

**EICAR.** The EICAR file is the industry-standard harmless test file. In PowerShell on an endpoint:

```powershell
Set-Content -Path "$env:TEMP\eicar.com" -Value 'X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*' -NoNewline -Encoding ascii
```

Keep the single quotes. SentinelOne may not react when the file is merely written. If nothing happens within a minute, ask the agent to scan the folder:

```powershell
$ctl = (Get-ChildItem "C:\Program Files\SentinelOne\Sentinel Agent *\SentinelCtl.exe" | Sort-Object LastWriteTime | Select-Object -Last 1).FullName
& $ctl scan_folder -i $env:TEMP
```

If the alert says the threat was **not mitigated** and the file is still there, your SentinelOne policy is in Detect mode: it reports threats and does not remove them. That is a policy decision worth making deliberately.

To replay any collected event through the rules, on the manager:

```bash
grep '"s1_type":"threat"' /var/log/sentinelone/sentinelone.json | tail -n 1 \
  | sudo /var/ossec/bin/wazuh-logtest 2>&1 | grep -E "^\s+(id|level|description):"
```

---

## Day to day

| Task | How |
|---|---|
| Renew the SentinelOne token | Generate a new token, put it in `/var/ossec/etc/s1_api.conf` (the `token =` line). No restart: the collector reads the file on every run. |
| See what is approved | `sudo usb-approve --list` |
| Check health | `sudo bash wazuh-s1-usb-install.sh status` |
| Update to a newer version | Download the new installer and run `install` again. Credentials and the approved list are kept. |
| Remove everything | `sudo bash wazuh-s1-usb-install.sh uninstall` |

## Where things are on the manager

| Path | What |
|---|---|
| `/var/ossec/etc/s1_api.conf` | SentinelOne URL, token and site ID. Root only. |
| `/var/ossec/integrations/sentinelone_pull.py` | The collector, run every 2 minutes by a `wodle command` block |
| `/var/ossec/var/s1_state.json` | How far the collector has read |
| `/var/log/sentinelone/sentinelone.json` | Collected events, one JSON object per line, rotated daily, 14 kept |
| `/var/ossec/etc/rules/9999_0009_sentinelone_rules.xml` | Rules 100600 to 100620 |
| `/var/ossec/etc/rules/9999_0010_usb_rules.xml` | Rules 101500 to 101508 |
| `/var/ossec/etc/rules/9999_0011_sentinelone_device_control_rules.xml` | Rules 101510 to 101515 |
| `/var/ossec/etc/rules/9999_0012_usb_approved_generated.xml` | Rules 101516 and 101517, written by `usb-approve` |
| `/var/ossec/etc/lists/approved_usb_serials` | The Approved USB list |
| `/usr/local/sbin/usb-approve` | The tool that maintains the list |
| `/root/wazuh-s1-usb-backup-*/` | Backups from each install, update and uninstall. Root only; they can hold a copy of the credentials file. |
