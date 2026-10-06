#!/usr/bin/env bash
# Test suite for wazuh-s1-usb-install.sh and usb-approve.
#
# Runs the real installer against a throw-away fake Wazuh tree. Wazuh itself is
# replaced by tests/fake/wazuh_emulator.py (see its header for what that does
# and does not prove) and the SentinelOne API by tests/fake/pylib/requests.py.
#
#   sudo bash tests/run-tests.sh          (root is needed: the installer insists on it)
set -u
HERE="$(cd "$(dirname "$0")" && pwd)"
REPO="$(dirname "$HERE")"
INSTALLER="$REPO/wazuh-s1-usb-install.sh"
PASS=0; FAIL=0
TOKEN="TESTTOKEN_abcdefghijklmnopqrstuvwxyz0123456789"

ok()   { PASS=$((PASS + 1)); printf '  ok    %s\n' "$1"; }
bad()  { FAIL=$((FAIL + 1)); printf '  FAIL  %s\n' "$1"; }
check(){ local name="$1"; shift; if "$@" >/dev/null 2>&1; then ok "$name"; else bad "$name"; fi; }
nope() { local name="$1"; shift; if "$@" >/dev/null 2>&1; then bad "$name"; else ok "$name"; fi; }
has()  { grep -qF -- "$2" "$1"; }
count(){ grep -cF -- "$2" "$1" || true; }

[ "$(id -u)" -eq 0 ] || { echo "run as root"; exit 1; }
python3 "$REPO/tools/build.py" --check >/dev/null 2>&1 && ok "built installer is up to date" || bad "built installer is up to date (run tools/build.py)"
bash -n "$INSTALLER" && ok "installer passes bash -n" || bad "installer passes bash -n"

mk_tree() {
  T=$(mktemp -d)
  O="$T/ossec"
  mkdir -p "$O"/{bin,etc/rules,etc/lists,etc/shared/default,integrations,var,logs/alerts,framework/python/bin} \
           "$T"/{sbin,logrotate.d,log,backup,path,s1}
  cat > "$O/etc/ossec.conf" <<'EOF'
<ossec_config>
  <global>
    <jsonout_output>yes</jsonout_output>
  </global>
  <ruleset>
    <decoder_dir>ruleset/decoders</decoder_dir>
    <rule_dir>ruleset/rules</rule_dir>
    <list>etc/lists/audit-keys</list>
    <list>etc/lists/security-eventchannel</list>
    <!-- <list>etc/lists/retired</list> -->
    <decoder_dir>etc/decoders</decoder_dir>
    <rule_dir>etc/rules</rule_dir>
  </ruleset>
</ossec_config>
EOF
  printf 'k:v\n' > "$O/etc/lists/audit-keys"; printf 'k:v\n' > "$O/etc/lists/security-eventchannel"
  printf '<group name="local,">\n  <rule id="100001" level="5">\n    <if_sid>5716</if_sid>\n    <description>local</description>\n  </rule>\n</group>\n' > "$O/etc/rules/local_rules.xml"
  printf '<agent_config>\n  <!-- Shared agent configuration here -->\n</agent_config>\n' > "$O/etc/shared/default/agent.conf"
  cat > "$O/bin/wazuh-control" <<EOF
#!/bin/sh
case "\$1" in
  info) echo "WAZUH_VERSION=\\"v\${FAKE_VERSION:-4.14.8}\\""; echo 'WAZUH_REVISION="rc1"'; echo "WAZUH_TYPE=\\"\${FAKE_TYPE:-server}\\"" ;;
  status) echo 'wazuh-analysisd is running...' ;;
esac
EOF
  cat > "$O/bin/wazuh-analysisd" <<EOF
#!/bin/sh
if [ -e "$O/.fail_when_installed" ] && [ -e "$O/etc/rules/9999_0010_usb_rules.xml" ]; then
  echo "2026/01/01 00:00:00 wazuh-analysisd: ERROR: forced by test"; exit 1
fi
WAZUH_HOME="$O" exec python3 "$HERE/fake/wazuh_emulator.py" check
EOF
  cat > "$O/bin/wazuh-logtest" <<EOF
#!/bin/sh
[ -e "$O/.break_logtest" ] && { cat >/dev/null; exit 0; }
WAZUH_HOME="$O" exec python3 "$HERE/fake/wazuh_emulator.py"
EOF
  printf '#!/bin/sh\nexit 0\n' > "$O/bin/wazuh-logcollector"
  cat > "$O/bin/verify-agent-conf" <<EOF
#!/bin/sh
for f in "$O"/etc/shared/*/agent.conf; do
  python3 -c "import sys,xml.etree.ElementTree as E; E.fromstring('<r>'+open(sys.argv[1]).read()+'</r>')" "\$f" || { echo "verify-agent-conf: ERROR in \$f"; exit 1; }
done
echo "verify-agent-conf: OK"
EOF
  cat > "$O/framework/python/bin/python3" <<EOF
#!/bin/sh
PYTHONPATH="$HERE/fake/pylib" PYTHONDONTWRITEBYTECODE=1 exec python3 "\$@"
EOF
  cat > "$T/path/systemctl" <<EOF
#!/bin/sh
echo "\$*" >> "$T/systemctl.log"
exit 0
EOF
  cat > "$T/path/curl" <<EOF
#!/bin/sh
echo "\$*" >> "$T/curl.args"
cat >> "$T/curl.stdin"
out=""
while [ \$# -gt 0 ]; do [ "\$1" = "-o" ] && out="\$2"; shift; done
[ -n "\$out" ] && echo '{}' > "\$out"
printf '%s' "\${FAKE_HTTP:-200}"
EOF
  chmod +x "$O"/bin/* "$O/framework/python/bin/python3" "$T"/path/*
  : > "$T/systemctl.log"; : > "$T/curl.args"; : > "$T/curl.stdin"
  # canned SentinelOne data, stamped one hour ago so the 24-hour first run picks it up
  python3 - "$REPO/tests/samples/selftest.tsv" "$T/s1" <<'EOF'
import datetime, json, sys
ts = (datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(hours=1)).strftime("%Y-%m-%dT%H:%M:%S.%fZ")
threats, acts = [], []
for line in open(sys.argv[1]):
    if line.startswith("#") or not line.strip():
        continue
    obj = json.loads(line.split("\t", 1)[1])
    if obj["s1_type"] == "threat":
        obj["s1"]["threatInfo"]["updatedAt"] = ts; threats.append(obj["s1"])
    elif obj["s1_type"] == "activity":
        obj["s1"]["createdAt"] = ts; acts.append(obj["s1"])
json.dump(threats, open(sys.argv[2] + "/threats.json", "w")); json.dump(acts, open(sys.argv[2] + "/activities.json", "w"))
EOF
  export WAZUH_HOME="$O" S1USB_LOGDIR="$T/log" S1USB_SBIN="$T/sbin" S1USB_LOGROTATE_D="$T/logrotate.d" \
         S1USB_BACKUP_ROOT="$T/backup" S1USB_NO_SLEEP=1 FAKE_S1_DIR="$T/s1" PATH="$T/path:$ORIG_PATH"
  unset FAKE_HTTP FAKE_S1_STATUS FAKE_VERSION FAKE_TYPE S1_API_TOKEN
}
rm_tree() { rm -rf "$T"; }
snap() { (cd "$T" && find ossec sbin logrotate.d log -type f ! -path 'ossec/bin/*' ! -path 'ossec/framework/*' -print0 | sort -z | xargs -0 sha256sum 2>/dev/null); }
run()  { "$INSTALLER" "$@" > "$T/out.txt" 2>&1; }
full() { S1_API_TOKEN="$TOKEN" run install --s1-url https://example.sentinelone.net/ --s1-site-id 1234567890 -y "$@"; }
ORIG_PATH="$PATH"

echo "== full install"
mk_tree; cp "$O/etc/ossec.conf" "$T/ossec.conf.orig"; cp "$O/etc/shared/default/agent.conf" "$T/agent.conf.orig"
full; RC=$?
check "exit code 0" test "$RC" -eq 0
for f in etc/s1_api.conf integrations/sentinelone_pull.py etc/rules/9999_0009_sentinelone_rules.xml \
         etc/rules/9999_0010_usb_rules.xml etc/rules/9999_0011_sentinelone_device_control_rules.xml etc/lists/approved_usb_serials; do
  check "installed $f" test -s "$O/$f"
done
check "usb-approve installed" test -x "$T/sbin/usb-approve"
check "logrotate file installed" test -s "$T/logrotate.d/sentinelone-wazuh"
check "credentials file is mode 600" test "$(stat -c %a "$O/etc/s1_api.conf")" = 600
check "credentials hold the URL without trailing slash" grep -qx 'url = https://example.sentinelone.net' "$O/etc/s1_api.conf"
check "token went to curl on stdin" has "$T/curl.stdin" "ApiToken $TOKEN"
nope  "token is not on curl's command line" has "$T/curl.args" "$TOKEN"
nope  "token is not in the installer output" has "$T/out.txt" "$TOKEN"
check "API test used the site ID" has "$T/curl.args" "siteIds=1234567890"
check "collector block added once" test "$(count "$O/etc/ossec.conf" 'BEGIN wazuh-s1-usb')" = 1
check "list registered once" test "$(count "$O/etc/ossec.conf" '<list>etc/lists/approved_usb_serials</list>')" = 1
check "list line sits inside <ruleset>, after the last live list" bash -c "grep -A1 'security-eventchannel' '$O/etc/ossec.conf' | grep -q approved_usb_serials"
check "ossec.conf still well-formed" python3 -c "import xml.etree.ElementTree as E; E.fromstring('<r>'+open('$O/etc/ossec.conf').read()+'</r>')"
check "agent.conf has the Windows block" has "$O/etc/shared/default/agent.conf" '<agent_config os="Windows">'
check "agent.conf has the Security query" has "$O/etc/shared/default/agent.conf" '(EventID = 4656 and Task = 12812)'
check "agent.conf has Partition/Diagnostic" has "$O/etc/shared/default/agent.conf" 'Microsoft-Windows-Partition/Diagnostic'
check "first run collected 5 threats" test "$(count "$T/log/sentinelone.json" '"s1_type":"threat"')" = 5
check "first run collected 9 activities" test "$(count "$T/log/sentinelone.json" '"s1_type":"activity"')" = 9
check "manager restarted once" test "$(count "$T/systemctl.log" 'restart wazuh-manager')" = 1
check "self-test passed 15 of 15" has "$T/out.txt" "15 of 15 sample events hit the expected rule"
check "backup folder is mode 700" test "$(stat -c %a "$T"/backup/wazuh-s1-usb-backup-*)" = 700
for f in 9999_0009_sentinelone_rules.xml 9999_0010_usb_rules.xml 9999_0011_sentinelone_device_control_rules.xml; do
  check "installed $f equals payload" cmp -s "$O/etc/rules/$f" "$REPO/payload/rules/$f"
done
check "installed poller equals payload (paths filled in)" bash -c "sed -e 's|@OSSEC@|$O|g' -e 's|@LOGDIR@|$T/log|g' '$REPO/payload/sentinelone_pull.py' | cmp -s - '$O/integrations/sentinelone_pull.py'"
nope  "no placeholders left in installed files" grep -rq '@OSSEC@\|@LOGDIR@' "$O/integrations" "$T/sbin"

echo "== run again (update, keep credentials)"
cp "$O/etc/s1_api.conf" "$T/cred.before"; LINES=$(wc -l < "$T/log/sentinelone.json")
run install -y; RC=$?
check "exit code 0" test "$RC" -eq 0
check "said it kept the credentials" has "$T/out.txt" "Keeping the saved SentinelOne credentials"
check "credentials unchanged" cmp -s "$O/etc/s1_api.conf" "$T/cred.before"
check "still one collector block" test "$(count "$O/etc/ossec.conf" 'BEGIN wazuh-s1-usb')" = 1
check "still one list line" test "$(count "$O/etc/ossec.conf" '<list>etc/lists/approved_usb_serials</list>')" = 1
check "still one agent block" test "$(count "$O/etc/shared/default/agent.conf" 'BEGIN wazuh-s1-usb')" = 1
check "second poll added no duplicate events" test "$(wc -l < "$T/log/sentinelone.json")" = "$LINES"

echo "== status and selftest"
run status; check "status exits 0" test $? -eq 0
check "status shows no devices yet" has "$T/out.txt" "(none yet)"
run selftest; check "selftest exits 0" test $? -eq 0

echo "== usb-approve"
UA() { WAZUH_HOME="$O" python3 "$T/sbin/usb-approve" "$@" > "$T/ua.txt" 2>&1; }
: > "$T/systemctl.log"
UA TESTSERIAL0001 Test drive one; check "add a device" test $? -eq 0
check "device is on the list" grep -qx 'TESTSERIAL0001:Test drive one' "$O/etc/lists/approved_usb_serials"
check "generated rules exist" has "$O/etc/rules/9999_0012_usb_approved_generated.xml" 'id="101517"'
check "manager restarted by usb-approve" test "$(count "$T/systemctl.log" 'restart wazuh-manager')" = 1
UA TESTSERIAL0002 DVD drive; check "add a second device" test $? -eq 0
UA TESTSERIAL0001 again; check "duplicate serial refused" test $? -ne 0
UA 'bad serial' x; check "serial with a space refused" test $? -ne 0
UA TESTSERIAL0003 'bad:label'; check "label with a colon refused" test $? -ne 0
UA --list; check "--list shows both" test "$(grep -c TESTSERIAL "$T/ua.txt")" = 2
WFAIL=0; WTOTAL=0
while IFS=$'\t' read -r exp json; do
  case "$exp" in ''|\#*) continue ;; esac
  WTOTAL=$((WTOTAL + 1))
  got=$(printf '%s\n' "$json" | "$O/bin/wazuh-logtest" 2>&1 | grep -E "^[[:space:]]+id: '" | head -n1 | grep -oE '[0-9]+' || true)
  [ "${got:-none}" = "$exp" ] || { WFAIL=$((WFAIL + 1)); echo "        windows sample expected $exp got ${got:-none}"; }
done < "$REPO/tests/samples/windows.tsv"
check "Windows sample events hit the expected rules ($WTOTAL samples)" test "$WFAIL" -eq 0
run status; check "status lists the approved device" has "$T/out.txt" "TESTSERIAL0001  Test drive one"
touch "$O/.fail_when_installed"; cp "$O/etc/lists/approved_usb_serials" "$T/list.before"
UA TESTSERIAL0009 should roll back; check "usb-approve fails when validation fails" test $? -ne 0
check "usb-approve restored the list" cmp -s "$O/etc/lists/approved_usb_serials" "$T/list.before"
nope  "usb-approve restored the generated rules" has "$O/etc/rules/9999_0012_usb_approved_generated.xml" TESTSERIAL0009
rm -f "$O/.fail_when_installed"
UA --remove TESTSERIAL0002; check "remove a device" test $? -eq 0
nope  "removed device is gone from the generated rule" has "$O/etc/rules/9999_0012_usb_approved_generated.xml" TESTSERIAL0002

echo "== uninstall"
run uninstall -y; RC=$?
check "exit code 0" test "$RC" -eq 0
check "ossec.conf is byte-identical to the original" cmp -s "$O/etc/ossec.conf" "$T/ossec.conf.orig"
check "agent.conf is byte-identical to the original" cmp -s "$O/etc/shared/default/agent.conf" "$T/agent.conf.orig"
nope  "no 9999_00* rule files left" bash -c "ls '$O'/etc/rules/9999_00* 2>/dev/null | grep -q ."
nope  "credentials removed" test -e "$O/etc/s1_api.conf"
nope  "usb-approve removed" test -e "$T/sbin/usb-approve"
check "collected events were kept" test -s "$T/log/sentinelone.json"
check "backup holds the removed list" bash -c "ls '$T'/backup/*/files'$O'/etc/lists/approved_usb_serials"
run uninstall -y; check "second uninstall stops cleanly" test $? -ne 0
rm_tree

echo "== failures leave the server untouched"
mk_tree; B=$(snap); touch "$O/.fail_when_installed"; B=$(snap)
full; check "validation failure: exit code 1" test $? -eq 1
check "validation failure: tree identical" test "$(snap)" = "$B"
check "validation failure: no restart" test "$(count "$T/systemctl.log" restart)" = 0
check "validation failure: said it rolled back" has "$T/out.txt" "Rolled back"
rm_tree
mk_tree; touch "$O/.break_logtest"; B=$(snap)
full; check "self-test failure: exit code 1" test $? -eq 1
check "self-test failure: tree identical" test "$(snap)" = "$B"
check "self-test failure: restarted twice (install, then rollback)" test "$(count "$T/systemctl.log" 'restart wazuh-manager')" = 2
rm_tree
mk_tree; printf '<group name="x,">\n  <rule id="100601" level="3">\n    <if_sid>5716</if_sid>\n    <description>x</description>\n  </rule>\n</group>\n' > "$O/etc/rules/other.xml"; B=$(snap)
full; check "rule ID collision: exit code 1" test $? -eq 1
check "rule ID collision: tree identical" test "$(snap)" = "$B"
check "rule ID collision: says nothing was changed" has "$T/out.txt" "Nothing was changed."
rm_tree
mk_tree; B=$(snap)
FAKE_HTTP=401 full; check "bad token (401): exit code 1" test $? -eq 1
check "bad token (401): tree identical" test "$(snap)" = "$B"
check "bad token (401): explains it is the token" has "$T/out.txt" "rejected the token"
FAKE_HTTP=403 full; check "wrong scope (403): explains role and scope" has "$T/out.txt" "role and scope"
rm_tree
mk_tree; sed -i 's|</ossec_config>|  <wodle name="command"><tag>sentinelone-pull</tag></wodle>\n</ossec_config>|' "$O/etc/ossec.conf"; B=$(snap)
full; check "hand-made collector block: exit code 1" test $? -eq 1
check "hand-made collector block: tree identical" test "$(snap)" = "$B"
rm_tree
mk_tree; B=$(snap)
FAKE_TYPE=agent full; check "not a manager: exit code 1" test $? -eq 1
FAKE_VERSION=4.2.7 full; check "Wazuh 4.2: exit code 1" test $? -eq 1
run install --s1-url http://example.sentinelone.net -y; check "no token: exit code 1" test $? -eq 1
S1_API_TOKEN="$TOKEN" run install --s1-url http://example.sentinelone.net -y; check "http:// URL refused" has "$T/out.txt" "must start with https://"
S1_API_TOKEN="$TOKEN" run install --s1-url https://example.sentinelone.net --s1-site-id 'abc' -y; check "non-numeric site ID refused" has "$T/out.txt" "site ID must be digits"
check "all refused runs left the tree identical" test "$(snap)" = "$B"
rm_tree

echo "== collector error is reported, not fatal"
mk_tree
FAKE_S1_STATUS=500 full; check "exit code 0" test $? -eq 0
check "warned about the collector error" has "$T/out.txt" "the collector reported an error"
check "error event written for Wazuh to alert on" has "$T/log/sentinelone.json" '"s1_type":"collector_error"'
rm_tree

echo "== --usb-only"
mk_tree
run install --usb-only -y; check "exit code 0" test $? -eq 0
check "USB rules installed" test -s "$O/etc/rules/9999_0010_usb_rules.xml"
nope  "no SentinelOne rules" test -e "$O/etc/rules/9999_0009_sentinelone_rules.xml"
nope  "no Device Control rules" test -e "$O/etc/rules/9999_0011_sentinelone_device_control_rules.xml"
nope  "no credentials file" test -e "$O/etc/s1_api.conf"
nope  "no collector block" has "$O/etc/ossec.conf" 'BEGIN wazuh-s1-usb'
check "list registered" has "$O/etc/ossec.conf" '<list>etc/lists/approved_usb_serials</list>'
check "curl never called" test ! -s "$T/curl.args"
check "self-test skipped with an explanation" has "$T/out.txt" "Self-test: skipped"
check "agent settings pushed" has "$O/etc/shared/default/agent.conf" 'BEGIN wazuh-s1-usb'
run uninstall -y; check "uninstall after --usb-only" test $? -eq 0
nope  "list line removed" has "$O/etc/ossec.conf" 'approved_usb_serials'
rm_tree

echo "== a broken agent.conf in another group"
mk_tree; mkdir -p "$O/etc/shared/broken"; printf '<agent_config>\n  <oops>\n</agent_config>\n' > "$O/etc/shared/broken/agent.conf"
full; check "pre-existing fault elsewhere does not block the install" test $? -eq 0
rm_tree
mk_tree; printf '#!/bin/sh\ngrep -q "BEGIN wazuh-s1-usb" "%s/etc/shared/default/agent.conf" && { echo "verify-agent-conf: ERROR"; exit 1; }\nexit 0\n' "$O" > "$O/bin/verify-agent-conf"; B=$(snap)
full; check "agent.conf that fails verification: exit code 1" test $? -eq 1
check "agent.conf that fails verification: tree identical" test "$(snap)" = "$B"
rm_tree

echo "== interactive install (answers typed at the prompts)"
if command -v script >/dev/null 2>&1; then
  mk_tree
  printf 'https://example.sentinelone.net/\n%s\n1234567890\ny\n' "$TOKEN" | script -qec "'$INSTALLER' install" /dev/null > "$T/out.txt" 2>&1
  check "exit code 0" test $? -eq 0
  check "asked for the URL" has "$T/out.txt" "SentinelOne console URL"
  check "asked for confirmation" has "$T/out.txt" "Continue? [y/N]"
  check "credentials saved from typed answers" grep -qx 'site_ids = 1234567890' "$O/etc/s1_api.conf"
  check "typed token saved" grep -qx "token = $TOKEN" "$O/etc/s1_api.conf"
  check "self-test passed" has "$T/out.txt" "15 of 15 sample events hit the expected rule"
  rm_tree
  mk_tree; B=$(snap)
  printf 'https://example.sentinelone.net/\n%s\n1234567890\nn\n' "$TOKEN" | script -qec "'$INSTALLER' install" /dev/null > "$T/out.txt" 2>&1
  check "answering no: exit code 1" test $? -eq 1
  check "answering no: tree identical" test "$(snap)" = "$B"
  rm_tree
else
  echo "  skip  'script' is not installed"
fi

echo "== an existing Approved USB list is kept"
mk_tree
printf 'PLACEHOLDER-NOT-A-DRIVE:old placeholder\nKEEPME000001:Existing drive\n' > "$O/etc/lists/approved_usb_serials"
sed -i 's|    <rule_dir>etc/rules</rule_dir>|    <list>etc/lists/approved_usb_serials</list>\n    <rule_dir>etc/rules</rule_dir>|' "$O/etc/ossec.conf"
full; check "exit code 0" test $? -eq 0
check "existing device kept" grep -qx 'KEEPME000001:Existing drive' "$O/etc/lists/approved_usb_serials"
check "list line not duplicated" test "$(count "$O/etc/ossec.conf" '<list>etc/lists/approved_usb_serials</list>')" = 1
check "self-test still passes 15 of 15" has "$T/out.txt" "15 of 15 sample events hit the expected rule"
check "generated rule covers the existing device" has "$O/etc/rules/9999_0012_usb_approved_generated.xml" 'KEEPME000001'
nope  "old placeholder is not treated as a device" has "$O/etc/rules/9999_0012_usb_approved_generated.xml" 'PLACEHOLDER'
rm_tree

echo "== agent.conf handling"
mk_tree
printf '<agent_config>\n  <localfile>\n    <location>Security</location>\n    <log_format>eventchannel</log_format>\n    <query>Event/System[EventID != 5145]</query>\n  </localfile>\n</agent_config>\n' > "$O/etc/shared/default/agent.conf"
full; check "existing Security block: exit code 0" test $? -eq 0
check "existing Security block is kept" has "$T/out.txt" "SECURITY=kept-existing"
check "only one Security block in agent.conf" test "$(count "$O/etc/shared/default/agent.conf" '<location>Security</location>')" = 1
check "Partition/Diagnostic still added" has "$O/etc/shared/default/agent.conf" 'Microsoft-Windows-Partition/Diagnostic'
check "prints the note about 4663" has "$T/out.txt" "does not exclude events 4663"
rm_tree
mk_tree; cp "$O/etc/shared/default/agent.conf" "$T/agent.conf.orig"; mkdir -p "$O/etc/shared/workstations"
full --no-agent-conf; check "--no-agent-conf: exit code 0" test $? -eq 0
check "--no-agent-conf: agent.conf untouched" cmp -s "$O/etc/shared/default/agent.conf" "$T/agent.conf.orig"
full --agent-group workstations --agent-group missing; check "two groups, one missing: exit code 0" test $? -eq 0
check "new agent.conf created for the group" has "$O/etc/shared/workstations/agent.conf" 'BEGIN wazuh-s1-usb'
check "missing group reported" has "$T/out.txt" "missing: group not found"
check "default group left alone when groups are named" cmp -s "$O/etc/shared/default/agent.conf" "$T/agent.conf.orig"
rm_tree

echo
echo "passed: $PASS   failed: $FAIL"
[ "$FAIL" -eq 0 ]
