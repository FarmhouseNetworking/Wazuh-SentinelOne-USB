#!/usr/bin/env python3
"""Build wazuh-s1-usb-install.sh from src/install.template.sh and payload/.

Each line of the form
    #%%EMBED <name> <path>%%
in the template becomes a shell function write_payload_<name> that prints the
file at <path>. Run from anywhere:  python3 tools/build.py
Run with --check to verify the built script is up to date (exit 1 if not).
"""
import os
import re
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TEMPLATE = os.path.join(ROOT, "src", "install.template.sh")
OUT = os.path.join(ROOT, "wazuh-s1-usb-install.sh")


def build():
    out = []
    for line in open(TEMPLATE).read().split("\n"):
        m = re.match(r"^#%%EMBED (\w+) (\S+)%%$", line)
        if not m:
            out.append(line)
            continue
        name, rel = m.groups()
        body = open(os.path.join(ROOT, rel)).read()
        if not body.endswith("\n"):
            body += "\n"
        marker = "__S1USB_EOF_%s__" % name.upper()
        if marker in body:
            sys.exit("payload %s contains its own heredoc marker" % rel)
        out.append("write_payload_%s() {\ncat <<'%s'\n%s%s\n}" % (name, marker, body, marker))
    return "\n".join(out)


def main():
    text = build()
    if "--check" in sys.argv:
        if not os.path.exists(OUT) or open(OUT).read() != text:
            sys.exit("wazuh-s1-usb-install.sh is out of date - run tools/build.py")
        print("up to date")
        return
    with open(OUT, "w") as f:
        f.write(text)
    os.chmod(OUT, 0o755)
    print("built %s (%d lines)" % (os.path.relpath(OUT, ROOT), text.count("\n")))


if __name__ == "__main__":
    main()
