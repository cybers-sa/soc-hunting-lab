#!/usr/bin/env python3
"""SOC Hunting Lab dashboard server."""
import csv
import json
import os
import re
import shutil
import subprocess
import sys
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs

csv.field_size_limit(sys.maxsize)
HERE = os.path.dirname(os.path.abspath(__file__))
LAB = os.path.dirname(HERE)
CASES = os.path.join(LAB, "cases")
PORT = int(os.environ.get("PORT", "8000"))
BUILTIN = {f"case-{i:02d}" for i in range(1, 8)}
EVTX_EXT = (".evtx",)
PCAP_EXT = (".pcap", ".pcapng", ".cap")
MAX_UPLOAD = 500 * 1024 * 1024
MAX_RAW = 20000

LEVELS = {"crit": "critical", "critical": "critical", "high": "high",
          "med": "medium", "medium": "medium", "low": "low",
          "info": "informational", "informational": "informational"}


def read_text(path):
    try:
        with open(path, encoding="utf-8", errors="replace") as f:
            return f.read()
    except OSError:
        return ""


def evidence_files(name):
    d = os.path.join(CASES, name, "evidence")
    return sorted(os.listdir(d)) if os.path.isdir(d) else []


def case_meta(name):
    readme = read_text(os.path.join(CASES, name, "README.md"))
    title = re.search(r"^#\s+(.+)$", readme, re.M)
    level = re.search(r"\*\*المستوى:\*\*\s*(.+)$", readme, re.M)
    info = {}
    try:
        info = json.load(open(os.path.join(CASES, name, "case.json"), encoding="utf-8"))
    except (OSError, ValueError):
        pass
    ev = evidence_files(name)
    res = os.path.join(CASES, name, "results")
    has_evtx = any(e.lower().endswith(EVTX_EXT) for e in ev)
    has_pcap = any(e.lower().endswith(PCAP_EXT) for e in ev)
    analyzed = (not has_evtx or os.path.isfile(os.path.join(res, "hayabusa.csv"))) and \
               (not has_pcap or os.path.isdir(os.path.join(res, "zeek"))) and bool(ev)
    return {
        "id": name,
        "title": info.get("title") or (title.group(1).strip() if title else name),
        "level": info.get("level") or (level.group(1).strip() if level else ""),
        "description": info.get("description", ""),
        "custom": name not in BUILTIN,
        "evidence": ev,
        "has_evtx": has_evtx,
        "has_pcap": has_pcap,
        "analyzed": analyzed,
        "readme": readme,
    }


def load_hayabusa(path):
    if not os.path.isfile(path):
        return None
    rows = []
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
    if not os.path.isdir(folder):
        return None
    rows = []
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


def parse_zeek_log(path):
    fields, rows = [], []
    with open(path, encoding="utf-8", errors="replace") as f:
        for line in f:
            line = line.rstrip("\n")
            if line.startswith("#fields"):
                fields = line.split("\t")[1:]
            elif line.startswith("#") or not line:
                continue
            elif fields:
                rows.append(dict(zip(fields, line.split("\t"))))
    return fields, rows


def load_zeek(folder):
    if not os.path.isdir(folder):
        return None
    logs = {}
    for root, _, files in os.walk(folder):
        for fn in sorted(files):
            if not fn.endswith(".log"):
                continue
            fields, rows = parse_zeek_log(os.path.join(root, fn))
            entry = logs.setdefault(fn[:-4], {"fields": [], "rows": []})
            for k in fields:
                if k not in entry["fields"]:
                    entry["fields"].append(k)
            entry["rows"].extend(rows)
    return logs


def load_notes(name):
    try:
        return json.load(open(os.path.join(CASES, name, "notes.json"), encoding="utf-8"))
    except (OSError, ValueError):
        return {}


def case_data(name):
    meta = case_meta(name)
    res = os.path.join(CASES, name, "results")
    meta["hayabusa"] = load_hayabusa(os.path.join(res, "hayabusa.csv"))
    meta["sigma"] = load_sigma(os.path.join(res, "chainsaw"))
    meta["zeek"] = load_zeek(os.path.join(res, "zeek"))
    meta["notes"] = load_notes(name)
    return meta


def flatten(obj, prefix="", out=None):
    out = {} if out is None else out
    if isinstance(obj, dict):
        for k, v in obj.items():
            k = k.replace("_attributes", "")
            flatten(v, f"{prefix}.{k}" if prefix else k, out)
    elif isinstance(obj, list):
        for i, v in enumerate(obj):
            flatten(v, f"{prefix}[{i}]", out)
    elif obj is not None and obj != "":
        out[prefix] = obj
    return out


def raw_events(name):
    ev_dir = os.path.join(CASES, name, "evidence")
    p = subprocess.run(["chainsaw", "dump", ev_dir, "--jsonl", "-q", "--skip-errors", "--extension", "evtx"],
                       capture_output=True, text=True)
    events, truncated = [], False
    for line in p.stdout.splitlines():
        if len(events) >= MAX_RAW:
            truncated = True
            break
        try:
            doc = json.loads(line)
        except ValueError:
            continue
        e = doc.get("Event", doc)
        sysf = e.get("System", {}) or {}
        data = e.get("EventData") or e.get("UserData") or {}
        events.append({
            "time": (sysf.get("TimeCreated_attributes") or {}).get("SystemTime", ""),
            "eid": sysf.get("EventID", ""),
            "record": sysf.get("EventRecordID", ""),
            "channel": sysf.get("Channel", ""),
            "provider": (sysf.get("Provider_attributes") or {}).get("Name", ""),
            "computer": sysf.get("Computer", ""),
            "data": flatten(data),
        })
    events.sort(key=lambda x: x["time"])
    return {"events": events, "truncated": truncated}


def run_analysis(name):
    case_dir = os.path.join(CASES, name)
    meta = case_meta(name)
    out = []
    ok = True
    res = os.path.join(case_dir, "results")
    if meta["has_evtx"]:
        p = subprocess.run([os.path.join(LAB, "bin", "hunt"), case_dir], cwd=LAB, capture_output=True, text=True)
        ok &= p.returncode == 0
        out.append(p.stdout + p.stderr)
    if meta["has_pcap"]:
        shutil.rmtree(os.path.join(res, "zeek"), ignore_errors=True)
        for f in meta["evidence"]:
            if f.lower().endswith(PCAP_EXT):
                dest = os.path.join(res, "zeek", os.path.splitext(f)[0])
                p = subprocess.run([os.path.join(LAB, "bin", "zeek-run"), os.path.join(case_dir, "evidence", f), dest],
                                   cwd=LAB, capture_output=True, text=True)
                ok &= p.returncode == 0
                out.append(p.stdout + p.stderr)
    return {"ok": ok, "output": "\n".join(out)[-4000:]}


def next_case_id():
    nums = [int(m.group(1)) for n in os.listdir(CASES) if (m := re.fullmatch(r"case-(\d+)", n))]
    return f"case-{max(nums + [7]) + 1:02d}"


def safe_filename(fn):
    fn = os.path.basename(fn).strip()
    fn = re.sub(r"[^\w.\- ]", "_", fn)
    return fn or "evidence"


class Handler(SimpleHTTPRequestHandler):
    def __init__(self, *a, **kw):
        super().__init__(*a, directory=HERE, **kw)

    def log_message(self, *args):
        pass

    def send_json(self, obj, code=200):
        body = json.dumps(obj, ensure_ascii=False, default=str).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def valid_case(self, name):
        return bool(name) and re.fullmatch(r"case-\d+", name) and os.path.isdir(os.path.join(CASES, name))

    def read_body(self, limit):
        n = int(self.headers.get("Content-Length") or 0)
        if n > limit:
            raise ValueError("too large")
        return self.rfile.read(n)

    def do_GET(self):
        url = urlparse(self.path)
        q = parse_qs(url.query)
        name = q.get("id", [""])[0]
        if url.path == "/api/cases":
            names = sorted(n for n in os.listdir(CASES) if re.fullmatch(r"case-\d+", n))
            out = []
            for n in names:
                m = case_meta(n)
                m.pop("readme", None)
                out.append(m)
            return self.send_json(out)
        if url.path in ("/api/case", "/api/raw"):
            if not self.valid_case(name):
                return self.send_json({"error": "not found"}, 404)
            return self.send_json(case_data(name) if url.path == "/api/case" else raw_events(name))
        if url.path.startswith("/api/"):
            return self.send_json({"error": "not found"}, 404)
        return super().do_GET()

    def do_POST(self):
        url = urlparse(self.path)
        q = parse_qs(url.query)
        name = q.get("id", [""])[0]
        if url.path == "/api/new":
            try:
                body = json.loads(self.read_body(64 * 1024) or b"{}")
            except ValueError:
                return self.send_json({"error": "bad request"}, 400)
            cid = next_case_id()
            os.makedirs(os.path.join(CASES, cid, "evidence"))
            info = {"title": str(body.get("title") or cid)[:120],
                    "description": str(body.get("description") or "")[:4000],
                    "level": "Custom"}
            with open(os.path.join(CASES, cid, "case.json"), "w", encoding="utf-8") as f:
                json.dump(info, f, ensure_ascii=False, indent=2)
            return self.send_json({"id": cid})
        if not self.valid_case(name):
            return self.send_json({"error": "not found"}, 404)
        if url.path == "/api/upload":
            fn = safe_filename(q.get("file", ["evidence"])[0])
            if not fn.lower().endswith(EVTX_EXT + PCAP_EXT):
                return self.send_json({"error": "Only .evtx, .pcap and .pcapng files are supported"}, 400)
            n = int(self.headers.get("Content-Length") or 0)
            if n > MAX_UPLOAD:
                return self.send_json({"error": "File is larger than 500 MB"}, 413)
            dest = os.path.join(CASES, name, "evidence", fn)
            with open(dest, "wb") as f:
                left = n
                while left > 0:
                    chunk = self.rfile.read(min(1 << 20, left))
                    if not chunk:
                        break
                    f.write(chunk)
                    left -= len(chunk)
            return self.send_json({"ok": True, "file": fn})
        if url.path == "/api/run":
            return self.send_json(run_analysis(name))
        if url.path == "/api/notes":
            try:
                notes = json.loads(self.read_body(2 * 1024 * 1024) or b"{}")
            except ValueError:
                return self.send_json({"error": "bad request"}, 400)
            with open(os.path.join(CASES, name, "notes.json"), "w", encoding="utf-8") as f:
                json.dump(notes, f, ensure_ascii=False, indent=2)
            return self.send_json({"ok": True})
        if url.path == "/api/delete":
            if name in BUILTIN:
                return self.send_json({"error": "Lab cases cannot be deleted"}, 400)
            shutil.rmtree(os.path.join(CASES, name), ignore_errors=True)
            return self.send_json({"ok": True})
        self.send_json({"error": "not found"}, 404)


if __name__ == "__main__":
    print(f"SOC Dashboard on http://localhost:{PORT}")
    ThreadingHTTPServer(("0.0.0.0", PORT), Handler).serve_forever()
