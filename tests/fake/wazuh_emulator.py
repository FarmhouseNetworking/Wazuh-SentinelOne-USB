#!/usr/bin/env python3
"""A small stand-in for wazuh-analysisd -t and wazuh-logtest, for the test suite.

It is NOT Wazuh. It checks the things that have actually gone wrong with these
rules on real managers, and it evaluates only the rule features these files use:

  check   - every rule file is well-formed; rule IDs are unique; every <if_sid>
            points at a rule loaded EARLIER (Wazuh loads all rule files in
            alphabetical order of file name) or at a stock rule (ID < 100000);
            every <list> used by a rule is registered in ossec.conf and exists.
  logtest - reads one JSON event per line and prints the rule that fires, in the
            same "id: 'N'" form wazuh-logtest prints. If two sibling rules both
            match, that is reported as an error instead of guessing the order.

Regular expressions are run with Python's re module, not PCRE2 or OS_Regex.
"""
import glob
import json
import os
import re
import sys
import xml.etree.ElementTree as ET

OSSEC = os.environ.get("WAZUH_HOME", "/var/ossec")

# Stand-ins for the stock Windows parent rules the USB rules hang off.
STOCK = {
    "60009": lambda e: e.get("win.system.severityValue") == "INFORMATION",
    "60103": lambda e: e.get("win.system.severityValue") == "AUDIT_SUCCESS",
    "60104": lambda e: e.get("win.system.severityValue") == "AUDIT_FAILURE",
    "60227": lambda e: e.get("win.system.severityValue") == "AUDIT_SUCCESS" and e.get("win.system.eventID") == "6416",
}


class Rule:
    def __init__(self, node, path):
        self.id = node.get("id")
        self.level = node.get("level")
        self.path = path
        self.if_sid = [x.strip() for n in node.findall("if_sid") for x in (n.text or "").split(",") if x.strip()]
        self.decoded_as = (node.findtext("decoded_as") or "").strip()
        self.unsupported = node.find("if_group") is not None or node.find("if_matched_group") is not None
        self.fields = [(f.get("name"), f.text or "", f.get("negate") == "yes") for f in node.findall("field")]
        self.lists = [(l.get("field"), l.get("lookup"), (l.text or "").strip()) for l in node.findall("list")]
        self.description = node.findtext("description") or ""


def load_rules():
    problems, rules = [], []
    for path in sorted(glob.glob(OSSEC + "/etc/rules/*.xml"), key=os.path.basename):
        try:
            root = ET.fromstring("<root>" + open(path).read() + "</root>")
        except ET.ParseError as e:
            problems.append("ERROR: (1226): Error reading XML file '%s': %s" % (path, e))
            continue
        for node in root.iter("rule"):
            rules.append(Rule(node, path))
    return rules, problems


def registered_lists():
    try:
        conf = re.sub(r"<!--.*?-->", "", open(OSSEC + "/etc/ossec.conf").read(), flags=re.S)
    except OSError:
        return set()
    return set(re.findall(r"<list>\s*([^<\s]+)\s*</list>", conf))


def check():
    rules, problems = load_rules()
    seen, lists = set(), registered_lists()
    for r in rules:
        if r.id in seen:
            problems.append("ERROR: Duplicate rule ID '%s' in %s" % (r.id, r.path))
        for sid in r.if_sid:
            if int(sid) >= 100000 and sid not in seen:
                problems.append("WARNING: (7619): Signature ID '%s' was not found. Invalid 'if_sid'. Rule '%s' will be ignored." % (sid, r.id))
        for _, _, lst in r.lists:
            if lst not in lists:
                problems.append("ERROR: List '%s' used by rule '%s' is not registered in ossec.conf" % (lst, r.id))
            elif not os.path.exists(os.path.join(OSSEC, lst)):
                problems.append("ERROR: List file '%s' used by rule '%s' does not exist" % (lst, r.id))
        seen.add(r.id)
    try:
        ET.fromstring("<root>" + open(OSSEC + "/etc/ossec.conf").read() + "</root>")
    except ET.ParseError as e:
        problems.append("ERROR: (1226): Error reading XML file 'etc/ossec.conf': %s" % e)
    for p in problems:
        print("2026/01/01 00:00:00 wazuh-analysisd: " + p)
    return 1 if any(p.startswith("ERROR") for p in problems) else 0


def flatten(obj, prefix="", out=None):
    out = {} if out is None else out
    for k, v in obj.items():
        key = prefix + k
        if isinstance(v, dict):
            flatten(v, key + ".", out)
        elif v is None:
            out[key] = "null"
        elif isinstance(v, bool):
            out[key] = "true" if v else "false"
        elif isinstance(v, list):
            out[key] = json.dumps(v)
        else:
            out[key] = str(v)
    return out


def list_keys(rel):
    keys = set()
    try:
        for line in open(os.path.join(OSSEC, rel)):
            if line.strip():
                keys.add(line.split(":", 1)[0])
    except OSError:
        pass
    return keys


def matches(rule, ev):
    if rule.unsupported:
        return False
    for name, pattern, negate in rule.fields:
        val = ev.get(name)
        if val is None:
            return False
        hit = re.search(pattern, val) is not None
        if hit == negate:
            return False
    for field, lookup, rel in rule.lists:
        val = ev.get(field)
        if val is None:
            return False
        if (val in list_keys(rel)) != (lookup == "match_key"):
            return False
    return True


def logtest():
    rules, problems = load_rules()
    if problems:
        sys.stderr.write("\n".join(problems) + "\n")
        return 1
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            ev = flatten(json.loads(line))
        except ValueError:
            sys.stderr.write("**Phase 2: no decoder matched\n")
            continue
        cands = [r for r in rules if not r.if_sid and r.decoded_as == "json" and "win.system.eventID" not in ev]
        stock = [sid for sid, fn in STOCK.items() if fn(ev)]
        current, parents = None, set(stock)
        hit = [r for r in cands if matches(r, ev)]
        if len(hit) > 1:
            sys.stderr.write("AMBIGUOUS root rules: %s\n" % [r.id for r in hit])
            continue
        if hit:
            current, parents = hit[0], {hit[0].id}
        while True:
            kids = [r for r in rules if set(r.if_sid) & parents and matches(r, ev)]
            if len(kids) > 1:
                # 60227 is itself a child of 60103: prefer the deeper stock parent's children
                deep = [r for r in kids if "60227" in r.if_sid]
                kids = deep if len(deep) == 1 else kids
            if len(kids) > 1:
                sys.stderr.write("AMBIGUOUS sibling rules: %s\n" % [r.id for r in kids])
                current = None
                break
            if not kids:
                break
            current, parents = kids[0], {kids[0].id}
        sys.stderr.write("**Phase 3: Completed filtering (rules).\n")
        if current is not None:
            sys.stderr.write("\tid: '%s'\n\tlevel: '%s'\n\tdescription: '%s'\n" % (current.id, current.level, current.description))
    return 0


if __name__ == "__main__":
    sys.exit(check() if sys.argv[1:] == ["check"] else logtest())
