"""Fake 'requests' for the test suite: serves canned SentinelOne API pages from
$FAKE_S1_DIR/threats.json and activities.json, honouring the <field>__gt filter."""
import json
import os


class _Resp:
    def __init__(self, status, body):
        self.status_code, self._body = status, body
        self.text = json.dumps(body)

    def json(self):
        return self._body


class Session:
    def __init__(self):
        self.headers = {}

    def get(self, url, params=None, timeout=None):
        status = int(os.environ.get("FAKE_S1_STATUS", "200"))
        if status != 200:
            return _Resp(status, {"errors": [{"title": "forced by test"}]})
        if not self.headers.get("Authorization", "").startswith("ApiToken "):
            return _Resp(401, {"errors": [{"title": "Authentication Failed"}]})
        name = "threats" if url.endswith("/threats") else "activities"
        items = json.load(open(os.path.join(os.environ["FAKE_S1_DIR"], name + ".json")))
        params = params or {}
        for k, v in params.items():
            if k.endswith("__gt"):
                f = k[:-4]
                items = [i for i in items if (i.get(f) or (i.get("threatInfo") or {}).get(f) or "") > v]
        return _Resp(200, {"data": items, "pagination": {"nextCursor": None}})
