# Troubleshooting

Every entry here is a problem that was actually hit while building this, or one the installer is written to catch.

Start with:

```bash
sudo bash wazuh-s1-usb-install.sh status      # on the manager
.\Test-UsbAuditing.ps1 -WriteTest             # on a Windows endpoint, as administrator
```

**When an alert is missing, find where the event stopped.** There are three places: the source never produced it, it never reached Wazuh, or it arrived and no rule matched. Check them in that order. More than once the cause was the first one, and time went into the other two.

---

## Installing

### "SentinelOne rejected the token (HTTP 401)"

The token itself is the problem, not the URL, the site ID or the firewall. A blocked connection gives no answer at all, and a scope problem gives 403.

- It was cut short when copied. SentinelOne tokens are long; the console shows them once.
- It expired, or was generated on a different console.
- It has spaces or line breaks in it. The installer strips those, so this only bites when you edit `s1_api.conf` by hand.

### "not allowed to read ... (HTTP 403)"

The token works but the service user cannot read that site. Check its scope includes the site and its role is at least Viewer. On a console shared by many customers (for example one run by a distributor), your own role may not be allowed to create site-scoped service users; ask whoever runs the console.

### Rule IDs already in use

The installer uses 100600 to 100629 and 101500 to 101519 and will not share them. It prints the files where it found them.

- If those files are an older, hand-made version of these same rules, see the next entry.
- If they are unrelated rules, move one side. These IDs are fixed in this version; renumbering means editing `payload/rules/*.xml`, the generated-rule IDs in `payload/usb-approve`, and the patterns in `src/install.template.sh`, then running `tools/build.py`.

Wazuh's own SentinelOne guide uses 100600 to 100604, so a manager set up from that guide will collide.

### Moving from a hand-made install

If the collector, rules or list were put in place by hand before this installer existed, the installer refuses to run over them: it cannot tell which lines in `ossec.conf` are yours. Remove the old pieces first, then install.

1. Back up `/var/ossec/etc/ossec.conf` and the old rule files.
2. In `ossec.conf`, delete the old `wodle command` block tagged `sentinelone-pull` and its `localfile` for `sentinelone.json`. Leave the `<list>etc/lists/approved_usb_serials</list>` line; the installer recognises it.
3. Move the old rule files that use these IDs out of `/var/ossec/etc/rules/`.
4. Keep `/var/ossec/etc/lists/approved_usb_serials` and `/var/ossec/etc/s1_api.conf` where they are. The installer keeps an existing list and existing credentials.
5. Run `install`. Then `usb-approve --rebuild` to regenerate the approved-device rules from your list.

If your old list has its own placeholder line (any key starting with `PLACEHOLDER-`), leave it. The installer adds the one line its self-test needs.

### "wazuh-analysisd -t already reports errors on this server"

Your configuration had a fault before the installer touched anything. Fix that first; the installer will not build on a broken base.

### The installer rolled back

It prints why. After a rollback the server is as it was, and the backup folder is kept. Two cases to know:

- **New warnings from wazuh-analysisd.** Any warning that was not there before counts as a failure, because Wazuh reports ignored rules as warnings, not errors.
- **Self-test failure.** The manager restarted with the new rules but a sample event hit the wrong rule, so everything was undone and the manager restarted a second time. Run `wazuh-analysisd -t` and look for warnings about rules being ignored.

---

## Rules

### A rule is "ignored" or never fires, with a warning about `if_sid` or `if_group`

Wazuh loads **all** rule files, stock and custom together, in alphabetical order of file name, whatever folder they are in. A rule can only refer to a rule or group that was loaded before it.

- A custom file named `0000_something.xml` loads before the whole stock ruleset, so every rule in it that builds on a stock rule is dropped.
- `9999_sentinelone.xml` loads **after** `9999_0010_usb.xml`, because digits sort before letters.

That is why these files are named `9999_0009_`, `9999_0010_`, `9999_0011_` and `9999_0012_`. If you rename them, keep that order.

Wazuh shows at most 50 such warnings per file, so a file where every rule is broken can look as if only some are.

### A Windows path in a rule does not match

Wazuh holds Windows event fields with every backslash doubled: a device ID that Windows shows as `USBSTOR\Disk&Ven_X\SERIAL&0` is `USBSTOR\\Disk&amp;Ven_X\\SERIAL&amp;0` inside Wazuh (and `&` is `&amp;`). A pattern that expects exactly one backslash between two words will not match. Use `\\+` in PCRE2 patterns, as rules 101500 and 101516 do.

### Rules 100611 to 100614 do not fire on something they should

They match on the English wording of SentinelOne's activity descriptions, which was not all available when they were written. Look at real events:

```bash
grep -o '"primaryDescription":"[^"]*"' /var/log/sentinelone/sentinelone.json | sort | uniq -c | sort -rn | head -n 40
```

and adjust the patterns in `9999_0009_sentinelone_rules.xml`.

---

## SentinelOne collection

### Collector errors (alert 100620)

```bash
grep collector_error /var/log/sentinelone/sentinelone.json | tail -n 3
```

| Error text | Cause | Fix |
|---|---|---|
| `HTTP 401` | Token expired or revoked | New token into the `token =` line of `/var/ossec/etc/s1_api.conf`. No restart needed. |
| `HTTP 400` mentioning `updatedAt` | This console does not accept that filter on threats | Change `threat_ts_field = updatedAt` to `createdAt` in `s1_api.conf`. Status changes to existing threats are then not re-sent. |
| A connection error | Outbound HTTPS blocked, DNS, or the console is down | Fix the network path. The collector catches up by itself. |
| `page cap hit` | More than 5,000 records in one run | Nothing; the backlog continues on the next run. |

### A burst of threat alerts after cleaning up the console

Resolving or re-classifying a threat changes its record, so the collector sends it again. Closing a dozen old threats produces a couple of dozen records. They arrive as 100605 (level 3) or 100606 (level 7), not as new detections.

### Nothing appears for an allowed USB device

SentinelOne reports devices it **blocks**. It does not report connections it allows, in the activity feed or in its Device Control event list. Rule 101512 exists in case that changes. The record of an allowed connection is the Windows event (101500, 101501, 101516, 101517).

Windows in turn logs event 6416 only for devices that get through. A blocked device produces a SentinelOne block record and no Windows event.

### EICAR is not detected

On the system this was built on, SentinelOne ignored the EICAR file when it was written and when it was launched, and flagged it during an on-demand folder scan. See SETUP.md, step 8.

A launch of `eicar.com` failing with "not compatible with the version of Windows" is Windows refusing to run a 16-bit program. It is not SentinelOne blocking it.

---

## USB auditing on Windows

### No alert when a file is copied to a USB drive

Work through these on the endpoint. `Test-UsbAuditing.ps1 -WriteTest` checks the first three for you.

1. **Is the audit policy on?** `auditpol /get /subcategory:"Removable Storage"` must show Success and Failure.
2. **Is `HotPlugSecureOpen` set to 1?** Without it the audit policy can show as enabled while Windows logs nothing for USB drives. This was the cause on the system this was built on: a USB DVD drive was audited, USB flash drives were not.
3. **Was the drive reconnected since?** A drive that was plugged in before the value was set is not audited until it is unplugged and plugged back in. No restart was needed.
4. **Does Windows log the event at all?**

   ```powershell
   Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4663; StartTime=(Get-Date).AddMinutes(-10)} -MaxEvents 5
   ```

   If this is empty after a copy, the problem is still on the endpoint and Wazuh is not involved yet.
5. **Does the agent forward it?** The Wazuh agent's built-in Security filter throws away 4663 and 4656. The pushed `agent.conf` block replaces that filter. Check what the agent is really using with the command in SETUP.md, step 4.

Nothing needs setting on the drive. A FAT32 drive cannot hold permissions or audit entries at all, and it is audited like any other.

### Does the pushed agent.conf really replace the agent's own Security block?

Yes, on Wazuh 4.14.8, confirmed by reading the agents' active configuration. Wazuh merges the pushed file with the agent's local `ossec.conf`; with one local Security block and one pushed block, the pushed one is used.

Do not push **two** Security blocks to the same agent (for example one in each of two groups the agent belongs to). The installer refuses to add its block to a group whose `agent.conf` already has one, for that reason. With three or more blocks for one channel, older Wazuh versions were reported to pick the second, not the last.

There is no need to edit each endpoint's local `ossec.conf`.

### An approved device shows as 101500, not 101516

The serial on the list does not match what the device reports.

- Look at the device ID in the 101500 alert. The serial is the last part, before `&amp;0`.
- The match ignores upper and lower case, but the serial must otherwise be exact.
- Some drives print one number on the case and report another over USB. Use the reported one.
- `usb-approve --list` shows what is on the list; `usb-approve --rebuild` regenerates the rule.

### An approved disk raises 101517 but no 101516, or the other way round

They come from two different Windows events. 101516 needs the Plug and Play audit policy (event 6416). 101517 needs the Partition/Diagnostic channel (event 1006), which the pushed agent settings collect and which does not exist for optical drives.

### A device reports a serial of all zeros

Common with USB-to-SATA adapters and some cheap drives. Do not approve it: an allow rule for that serial would allow every device that reports it.

### Writing to an approved drive raises 101507 (level 10)

101507 fires when a file is written on a computer where a **non-approved** USB storage device connected in the last hour. Approved devices raise 101516/101517, which are deliberately left out of that correlation. So either a second, non-approved device was connected in that hour, or the approved device was not recognised (see "An approved device shows as 101500").

### File counts look too high

Windows often logs two 4663 events for one copied file. Count files by distinct name, not by alert.

### Phones and cameras

Rule 101500 also fires for devices that connect as media devices (their Windows device ID starts with `SWD\WPD`). A SentinelOne rule that blocks USB **mass storage** (class 08) does not cover those; check your Device Control policy if you need them blocked.

---

## usb-approve

### "VALIDATION FAILED - list and rules restored, manager NOT restarted"

`wazuh-analysisd -t` reported an error or a warning about the list or the generated rules after the change. The list and rules were put back. Run `sudo /var/ossec/bin/wazuh-analysisd -t` to see the message; the usual cause is a fault somewhere else in the configuration that appeared since the last restart.

### "rule ID 101516 or 101517 is already used"

Another rule file uses the two IDs reserved for the generated rules. Move those rules to other IDs.
