#!/usr/bin/env python3
"""Kleenscan API client for the Talon C2 hardening mission (stdlib only).

Usage:
  python3 kleenscan.py avlist
  python3 kleenscan.py static  <file> [avList]          # submit, wait, print results
  python3 kleenscan.py runtime <file> [avList]          # submit (connect_internet=false), wait, print results
  python3 kleenscan.py sha256 <file>

Cost model tracked in tests.log: static ~$0.10/request, runtime ~$1.00/request.
"""
import hashlib
import json
import os
import subprocess
import sys
import time
from urllib import request as urlrequest

BASE = "https://www.kleenscan.biz/api/v1"


def _load_token():
    # Token lives outside the repo: $KLEENSCAN_TOKEN or tools/.kleenscan_token (gitignored).
    tok = os.environ.get("KLEENSCAN_TOKEN")
    if tok:
        return tok.strip()
    path = os.path.join(os.path.dirname(os.path.abspath(__file__)), ".kleenscan_token")
    with open(path) as f:
        return f.read().strip()


TOKEN = _load_token()


def die(msg):
    print(f"[-] {msg}", file=sys.stderr)
    sys.exit(1)


def sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def api_get(url):
    req = urlrequest.Request(url, headers={"X-Auth-Token": TOKEN})
    with urlrequest.urlopen(req, timeout=60) as r:
        return json.loads(r.read().decode())


def api_post_multipart(url, file_path, fields):
    cmd = ["curl", "-sS", "-X", "POST", url, "-H", f"X-Auth-Token: {TOKEN}"]
    for key, value in fields.items():
        cmd += ["-F", f"{key}={value}"]
    cmd += ["-F", f"path=@{file_path};type=application/octet-stream"]
    for attempt in (1, 2):
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
        if proc.returncode == 0 and proc.stdout.strip():
            return json.loads(proc.stdout)
        print(f"[!] curl attempt {attempt} empty/failed (rc={proc.returncode}) — NOTE: possible orphaned submission, check tests.log", file=sys.stderr)
        time.sleep(5)
    die(f"curl failed after retries: rc={proc.returncode} err={proc.stderr} out={proc.stdout!r}")


def api_post_json(url, payload=None):
    data = json.dumps(payload or {}).encode()
    req = urlrequest.Request(
        url,
        data=data,
        headers={"X-Auth-Token": TOKEN, "Content-Type": "application/json"},
        method="POST",
    )
    with urlrequest.urlopen(req, timeout=60) as r:
        return json.loads(r.read().decode())


def extract_token(payload):
    data = payload.get("data")
    if isinstance(data, list) and data:
        item = data[0]
        if isinstance(item, dict) and "scan_token" in item:
            return item["scan_token"]
    if isinstance(data, dict) and "scan_token" in data:
        return data["scan_token"]
    if isinstance(data, str):
        return data
    return None


def cmd_avlist():
    print(json.dumps(api_get(BASE + "/get/avlist"), indent=2))


def submit(kind, path, avlist_str, connect_internet=None):
    fields = {"avList": avlist_str}
    if kind == "runtime" and connect_internet is not None:
        fields["connect_internet"] = "true" if connect_internet else "false"
    payload = api_post_multipart(f"{BASE}/{kind}/scan", path, fields)
    print(f"[+] {kind} submit response: {json.dumps(payload)}")
    if not payload.get("success"):
        die(f"submit failed: {payload.get('message')}")
    token = extract_token(payload)
    if not token:
        die("no scan_token in response")
    return token


def wait_static(token, max_wait=900):
    start = time.time()
    while True:
        payload = api_get(f"{BASE}/file/result/{token}")
        results = payload.get("data", [])
        pending = [x for x in results if x.get("status") not in ("ok", "failed", "timeout")]
        if not pending or time.time() - start > max_wait:
            return payload
        print(f"[.] static scan pending ({int(time.time() - start)}s)")
        time.sleep(15)


def wait_runtime(token, max_wait=2700):
    start = time.time()
    while True:
        payload = api_get(f"{BASE}/runtime/status/{token}")
        try:
            status = int(payload.get("data", 2))
        except (TypeError, ValueError):
            status = 2
        print(f"[.] runtime status: {status} ({int(time.time() - start)}s elapsed)")
        if status == 3 or time.time() - start > max_wait:
            break
        time.sleep(30)
    return api_post_json(f"{BASE}/runtime/result/{token}", {"screenshots": False})


def main():
    if len(sys.argv) < 2:
        die(__doc__)
    cmd = sys.argv[1]
    if cmd == "avlist":
        cmd_avlist()
    elif cmd == "sha256":
        print(sha256(sys.argv[2]))
    elif cmd in ("static", "runtime"):
        path = sys.argv[2]
        avlist_str = sys.argv[3] if len(sys.argv) > 3 else "all"
        print(f"[+] sha256({path}) = {sha256(path)}")
        token = submit(cmd, path, avlist_str, connect_internet=False if cmd == "runtime" else None)
        print(f"[+] scan_token = {token}")
        payload = wait_static(token) if cmd == "static" else wait_runtime(token)
        print(f"[=] FINAL RESULTS:\n{json.dumps(payload, indent=2)}")
    elif cmd == "wait-static":
        payload = wait_static(sys.argv[2])
        print(f"[=] STATIC RESULTS:\n{json.dumps(payload, indent=2)}")
    elif cmd == "wait-runtime":
        payload = wait_runtime(sys.argv[2])
        print(f"[=] RUNTIME RESULTS:\n{json.dumps(payload, indent=2)}")
    else:
        die(__doc__)


if __name__ == "__main__":
    main()
