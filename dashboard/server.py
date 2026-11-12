#!/usr/bin/env python3
"""SOC Hunting Lab dashboard server."""
import csv
import json
import os
import re
import subprocess
import sys
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs

csv.field_size_limit(sys.maxsize)
HERE = os.path.dirname(os.path.abspath(__file__))
LAB = os.path.dirname(HERE)
CASES = os.path.join(LAB, "cases")
PORT = int(os.environ.get("PORT", "8000"))

LEVELS = {"crit": "critical", "critical": "critical", "high": "high",
          "med": "medium", "medium": "medium", "low": "low",
          "info": "informational", "informational": "informational"}


def read_text(path):
    try:
        with open(path, encoding="utf-8", errors="replace") as f:
            return f.read()
    except OSError:
        return ""


def case_meta(name):
    readme = read_text(os.path.join(CASES, name, "README.md"))
    title = re.search(r"^#\s+(.+)$", readme, re.M)
    level = re.search(r"\*\*المستوى:\*\*\s*(.+)$", readme, re.M)
    evidence_dir = os.path.join(CASES, name, "evidence")
    evidence = sorted(os.listdir(evidence_dir)) if os.path.isdir(evidence_dir) else []
    kind = "network" if any(e.endswith((".pcap", ".pcapng")) for e in evidence) else "windows"
    return {
        "id": name,
        "title": title.group(1).strip() if title else name,
        "level": level.group(1).strip() if level else "",
        "kind": kind,
        "evidence": evidence,
        "readme": readme,
    }


def load_hayabusa(path):
    rows = []
    if not os.path.isfile(path):
        return None
    with open(path, encoding="utf-8", errors="replace", newline="") as f:
        for r in csv.DictReader(f):
            rows.append({
                "time": r.get("Timestamp", ""),
                "rule": r.get("RuleTitle", ""),
                "level": LEVELS.get(r.get("Level", "").lower(), r.get("Level", "")),
                "computer": r.get("Computer", ""),
                "channel": r.get("Channel", ""),
                "eid": r.get("EventID", ""),
                "record": r.get("RecordID", ""),
                "details": r.get("Details", ""),
                "extra": r.get("ExtraFieldInfo", ""),
            })
    return rows


def load_sigma(folder):
    rows = []
    if not os.path.isdir(folder):
        return None
    for fn in sorted(os.listdir(folder)):
        if not fn.endswith(".csv"):
            continue
        with open(os.path.join(folder, fn), encoding="utf-8", errors="replace", newline="") as f:
            for r in csv.DictReader(f):
                rows.append({
                    "time": r.get("timestamp", ""),
                    "rules": [d for d in r.get("detections", "").split(";") if d],
                    "computer": r.get("Computer", ""),
                    "eid": r.get("Event ID", ""),
                    "record": r.get("Record ID", ""),
                    "data": r.get("Event Data", ""),
                })
    return rows


def load_zeek(folder):
    if not os.path.isdir(folder):
        return None
    logs = {}
    for fn in sorted(os.listdir(folder)):
        if not fn.endswith(".log"):
            continue
        fields, rows = [], []
        with open(os.path.join(folder, fn), encoding="utf-8", errors="replace") as f:
            for line in f:
                line = line.rstrip("\n")
                if line.startswith("#fields"):
                    fields = line.split("\t")[1:]
                elif line.startswith("#") or not line:
                    continue
                elif fields:
                    rows.append(dict(zip(fields, line.split("\t"))))
        logs[fn[:-4]] = {"fields": fields, "rows": rows}
    return logs


def case_data(name):
    meta = case_meta(name)
    res = os.path.join(CASES, name, "results")
    meta["hayabusa"] = load_hayabusa(os.path.join(res, "hayabusa.csv"))
    meta["sigma"] = load_sigma(os.path.join(res, "chainsaw"))
    meta["zeek"] = load_zeek(os.path.join(res, "zeek"))
    return meta


def run_analysis(name):
    case_dir = os.path.join(CASES, name)
    meta = case_meta(name)
    if meta["kind"] == "network":
        pcap = os.path.join(case_dir, "evidence", meta["evidence"][0])
        cmd = [os.path.join(LAB, "bin", "zeek-run"), pcap]
    else:
        cmd = [os.path.join(LAB, "bin", "hunt"), case_dir]
    p = subprocess.run(cmd, cwd=LAB, capture_output=True, text=True)
    return {"ok": p.returncode == 0, "output": (p.stdout + p.stderr)[-4000:]}


class Handler(SimpleHTTPRequestHandler):
    def __init__(self, *a, **kw):
        super().__init__(*a, directory=HERE, **kw)

    def log_message(self, *args):
        pass

    def send_json(self, obj, code=200):
        body = json.dumps(obj, ensure_ascii=False).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def valid_case(self, name):
        return bool(name) and re.fullmatch(r"case-\d+", name) and os.path.isdir(os.path.join(CASES, name))

    def do_GET(self):
        url = urlparse(self.path)
        q = parse_qs(url.query)
        if url.path == "/api/cases":
            names = sorted(n for n in os.listdir(CASES) if re.fullmatch(r"case-\d+", n))
            out = []
            for n in names:
                m = case_meta(n)
                m.pop("readme", None)
                res = os.path.join(CASES, n, "results")
                m["analyzed"] = os.path.isfile(os.path.join(res, "hayabusa.csv")) or os.path.isdir(os.path.join(res, "zeek"))
                out.append(m)
            return self.send_json(out)
        if url.path == "/api/case":
            name = q.get("id", [""])[0]
            if not self.valid_case(name):
                return self.send_json({"error": "not found"}, 404)
            return self.send_json(case_data(name))
        return super().do_GET()

    def do_POST(self):
        url = urlparse(self.path)
        q = parse_qs(url.query)
        if url.path == "/api/run":
            name = q.get("id", [""])[0]
            if not self.valid_case(name):
                return self.send_json({"error": "not found"}, 404)
            return self.send_json(run_analysis(name))
        self.send_json({"error": "not found"}, 404)


if __name__ == "__main__":
    print(f"SOC Dashboard on http://localhost:{PORT}")
    ThreadingHTTPServer(("0.0.0.0", PORT), Handler).serve_forever()
