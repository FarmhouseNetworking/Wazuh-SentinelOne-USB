#!/usr/bin/env python3
"""SentinelOne -> Wazuh API poller.

Pulls threats (by updatedAt) and activities (by createdAt) changed since the
last run and writes one JSON object per line for the Wazuh logcollector:

  {"integration":"sentinelone","s1_type":"threat|activity|collector_error","s1":{...}}

Any failure is written as an s1_type=collector_error event, so Wazuh raises an
alert when collection breaks (expired token, API error, network).

Installed and configured by wazuh-s1-usb-install.sh. Paths below are filled in
at install time.
"""
import configparser
import datetime
import json
import os
import sys

import requests

CONF = "@OSSEC@/etc/s1_api.conf"
STATE = "@OSSEC@/var/s1_state.json"
OUT = "@LOGDIR@/sentinelone.json"
FIRST_RUN_LOOKBACK_HOURS = 24
PAGE_LIMIT = 100
MAX_PAGES = 50
MAX_LINE = 60000  # Wazuh drops events longer than about 64 KB
UTC = datetime.timezone.utc


def iso(dt):
    return dt.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def parse(ts):
    try:
        return datetime.datetime.fromisoformat(str(ts).replace("Z", "+00:00"))
    except Exception:
        return None


def default_state():
    start = iso(datetime.datetime.now(UTC) - datetime.timedelta(hours=FIRST_RUN_LOOKBACK_HOURS))
    return {"threat": start, "activity": start}


def load_state():
    try:
        with open(STATE) as f:
            return json.load(f)
    except Exception:
        return default_state()


def save_state(state):
    tmp = STATE + ".tmp"
    with open(tmp, "w") as f:
        json.dump(state, f)
    os.replace(tmp, STATE)


def emit(fh, s1_type, obj):
    rec = {"integration": "sentinelone", "s1_type": s1_type, "s1": obj}
    line = json.dumps(rec, separators=(",", ":"), default=str)
    if len(line) > MAX_LINE and isinstance(obj, dict):
        for k in ("indicators", "whiteningOptions", "mitigationStatus"):
            obj.pop(k, None)
        line = json.dumps(rec, separators=(",", ":"), default=str)
    if len(line) > MAX_LINE:
        line = json.dumps({"integration": "sentinelone", "s1_type": "collector_error",
                           "s1": {"source": s1_type,
                                  "error": "event %s too large to forward" % obj.get("id")}})
    fh.write(line + "\n")


def fetch(sess, base, path, ts_field, since, site_ids):
    params = {"limit": PAGE_LIMIT, ts_field + "__gt": since}
    if site_ids:
        params["siteIds"] = site_ids
    items, cursor = [], None
    for _ in range(MAX_PAGES):
        if cursor:
            params["cursor"] = cursor
        r = sess.get(base + path, params=params, timeout=30)
        if r.status_code != 200:
            raise RuntimeError("HTTP %s from %s: %s" % (r.status_code, path, r.text[:300]))
        body = r.json()
        items.extend(body.get("data") or [])
        cursor = (body.get("pagination") or {}).get("nextCursor")
        if not cursor:
            return items, False
    return items, True


def main():
    cfg = configparser.ConfigParser(interpolation=None)
    cfg.read(CONF)
    s = cfg["s1"]
    base = s["url"].rstrip("/")
    sites = s.get("site_ids", "").strip()
    threat_field = s.get("threat_ts_field", "updatedAt").strip() or "updatedAt"

    sess = requests.Session()
    sess.headers.update({"Authorization": "ApiToken " + s["token"],
                         "Content-Type": "application/json"})
    state = load_state()
    os.makedirs(os.path.dirname(OUT), exist_ok=True)

    jobs = [("threat", "/web/api/v2.1/threats", threat_field),
            ("activity", "/web/api/v2.1/activities", "createdAt")]

    with open(OUT, "a") as fh:
        for s1_type, path, field in jobs:
            try:
                since = state.get(s1_type) or default_state()[s1_type]
                items, truncated = fetch(sess, base, path, field, since, sites)
                newest, newest_dt = since, parse(since)
                for it in items:
                    emit(fh, s1_type, it)
                    ts = it.get(field) or (it.get("threatInfo") or {}).get(field)
                    d = parse(ts) if ts else None
                    if d and (newest_dt is None or d > newest_dt):
                        newest, newest_dt = ts, d
                state[s1_type] = newest
                if truncated:
                    emit(fh, "collector_error", {"source": s1_type,
                         "error": "page cap hit (%d) - backlog continues next run" % (PAGE_LIMIT * MAX_PAGES)})
            except Exception as e:
                emit(fh, "collector_error", {"source": s1_type, "error": str(e)[:500]})
    save_state(state)


if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        try:
            with open(OUT, "a") as fh:
                emit(fh, "collector_error", {"source": "main", "error": str(e)[:500]})
        finally:
            sys.exit(1)
