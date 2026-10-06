#!/usr/bin/env python3
"""Config edits for wazuh-s1-usb-install.sh. Not meant to be run by hand.

Every edit is refused (exit 3, file untouched) if it would turn a well-formed
file into one that is not.
"""
import os
import re
import sys

BEGIN = "<!-- BEGIN wazuh-s1-usb (managed by wazuh-s1-usb-install.sh; do not edit inside) -->"
END = "<!-- END wazuh-s1-usb -->"
BLOCK_RE = re.compile(r"<!-- BEGIN wazuh-s1-usb[^\n]*-->.*?<!-- END wazuh-s1-usb -->\n?", re.S)
COMMENT_RE = re.compile(r"<!--.*?-->", re.S)


def wellformed(text):
    import xml.etree.ElementTree as ET
    body = re.sub(r"^\s*<\?xml[^>]*\?>", "", text)
    try:
        ET.fromstring("<root>" + body + "</root>")
        return True
    except ET.ParseError:
        return False


def read(path):
    with open(path) as f:
        return f.read()


def write(path, old, new):
    if old is not None and wellformed(old) and not wellformed(new):
        sys.stderr.write("refusing to write %s: result would not be well-formed XML\n" % path)
        sys.exit(3)
    if new == old:
        return
    with open(path, "w") as f:
        f.write(new)


def with_block(text, body):
    text = BLOCK_RE.sub("", text)
    if text and not text.endswith("\n"):
        text += "\n"
    return text + BEGIN + "\n" + body.rstrip("\n") + "\n" + END + "\n"


def ossec_block_set(conf, blockfile):
    old = read(conf)
    write(conf, old, with_block(old, read(blockfile)))


def block_del(conf):
    if not os.path.exists(conf):
        return
    old = read(conf)
    write(conf, old, BLOCK_RE.sub("", old))


def active_spans(text, pattern):
    """Matches of pattern that are not inside an XML comment."""
    comments = [(m.start(), m.end()) for m in COMMENT_RE.finditer(text)]
    out = []
    for m in re.finditer(pattern, text, flags=re.M):
        if not any(a <= m.start() < b for a, b in comments):
            out.append(m)
    return out


def list_add(conf, listpath):
    old = read(conf)
    line_re = r"^([ \t]*)<list>[^<\n]*</list>[ \t]*\n"
    if any(listpath in m.group(0) for m in active_spans(old, line_re)):
        return
    lists = active_spans(old, line_re)
    if lists:
        m = lists[-1]
        new = old[:m.end()] + m.group(1) + "<list>" + listpath + "</list>\n" + old[m.end():]
    else:
        ends = active_spans(old, r"^([ \t]*)</ruleset>")
        if not ends:
            sys.stderr.write("no <ruleset> section found in %s\n" % conf)
            sys.exit(4)
        m = ends[0]
        new = old[:m.start()] + m.group(1) + "  <list>" + listpath + "</list>\n" + old[m.start():]
    write(conf, old, new)


def list_del(conf, listpath):
    old = read(conf)
    new = re.sub(r"^[ \t]*<list>" + re.escape(listpath) + r"</list>[ \t]*\n", "", old, flags=re.M)
    write(conf, old, new)


def agent_set(conf, security_file, partition_file):
    old = read(conf) if os.path.exists(conf) else None
    base = BLOCK_RE.sub("", old or "")
    visible = COMMENT_RE.sub("", base)
    parts = []
    if re.search(r"<location>\s*Security\s*</location>", visible):
        print("SECURITY=kept-existing")
    else:
        parts.append(read(security_file).rstrip("\n"))
        print("SECURITY=added")
    if re.search(r"<location>\s*Microsoft-Windows-Partition/Diagnostic\s*</location>", visible):
        print("PARTITION=kept-existing")
    else:
        parts.append(read(partition_file).rstrip("\n"))
        print("PARTITION=added")
    if parts:
        body = '<agent_config os="Windows">\n\n' + "\n\n".join(parts) + "\n\n</agent_config>"
        new = with_block(base, body)
    else:
        new = base
    if old is None:
        with open(conf, "w") as f:
            f.write(new)
    else:
        write(conf, old, new)


def main(a):
    cmd = a[0]
    if cmd == "ossec-block-set":
        ossec_block_set(a[1], a[2])
    elif cmd in ("ossec-block-del", "agent-del"):
        block_del(a[1])
    elif cmd == "list-add":
        list_add(a[1], a[2])
    elif cmd == "list-del":
        list_del(a[1], a[2])
    elif cmd == "agent-set":
        agent_set(a[1], a[2], a[3])
    else:
        sys.exit("unknown command")


if __name__ == "__main__":
    main(sys.argv[1:])
