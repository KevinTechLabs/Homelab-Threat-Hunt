"""Parse the three sources into pandas DataFrames (pickled for the hunts)."""
import glob, gzip, json, re, sys
from pathlib import Path
import pandas as pd

D = Path(sys.argv[1])
OUT = Path(sys.argv[2]); OUT.mkdir(exist_ok=True)

# ---- Suricata fast log
SUR = re.compile(r'^(\d\d/\d\d/\d{4}-\d\d:\d\d:\d\d\.\d+)\s+\[\*\*\]\s+\[(\d+):(\d+):(\d+)\]\s+(.*?)\s+\[\*\*\]\s+\[Classification:\s*(.*?)\]\s+\[Priority:\s*(\d+)\]\s+\{(\w+)\}\s+(\S+?)(?::(\d+))?\s+->\s+(\S+?)(?::(\d+))?$')
rows, bad = [], 0
for f in glob.glob(str(D / "pfsense/var/log/suricata/*/alerts.log")):
    for line in open(f, errors="replace"):
        m = SUR.match(line.strip())
        if not m: bad += 1; continue
        g = m.groups()
        rows.append(dict(ts=g[0], gid=int(g[1]), sid=int(g[2]), rev=int(g[3]), sig=g[4], cls=g[5], prio=int(g[6]),
                         proto=g[7], src=g[8], sport=g[9], dst=g[10], dport=g[11]))
s = pd.DataFrame(rows); s["ts"] = pd.to_datetime(s.ts, format="%m/%d/%Y-%H:%M:%S.%f")
s.to_pickle(OUT / "suricata.pkl"); print("suricata", len(s), "unparsed", bad, s.ts.min(), s.ts.max())

# ---- pfSense filterlog
rows, bad = [], 0
for f in sorted(glob.glob(str(D / "pfsense/var/log/filter.log*"))):
    if f.endswith(".bz2"): continue
    for line in open(f, errors="replace"):
        if "filterlog" not in line: continue
        head, _, csv = line.partition("]: ")
        p = csv.strip().split(",")
        try:
            r = dict(ts=" ".join(head.split()[:3]), rule=p[0], tracker=p[3], iface=p[4], reason=p[5], action=p[6], dir=p[7], ipv=p[8])
            if p[8] == "4":
                r.update(proto=p[16], src=p[18], dst=p[19]); rest = p[20:]
            elif p[8] == "6":
                r.update(proto=p[12].lower(), src=p[15], dst=p[16]); rest = p[17:]
            else:
                bad += 1; continue
            if r["proto"] in ("tcp", "udp") and len(rest) >= 2:
                r.update(sport=rest[0], dport=rest[1])
                if r["proto"] == "tcp" and len(rest) > 3: r["tcpflags"] = rest[3]
            rows.append(r)
        except IndexError:
            bad += 1
fl = pd.DataFrame(rows).drop_duplicates()
fl["ts"] = pd.to_datetime("2026 " + fl.ts, format="%Y %b %d %H:%M:%S")
fl.to_pickle(OUT / "filter.pkl"); print("filter", len(fl), "unparsed", bad, fl.ts.min(), fl.ts.max())

# ---- Wazuh alerts
rows, bad = [], 0
files = glob.glob(str(D / "wazuh/**/*.json"), recursive=True)
for f in files:
    for line in open(f, errors="replace"):
        try: a = json.loads(line)
        except Exception: bad += 1; continue
        r = a.get("rule", {}); ag = a.get("agent", {}); data = a.get("data", {}) or {}
        rows.append(dict(ts=a.get("timestamp"), id=a.get("id"), level=r.get("level"), rule_id=r.get("id"), desc=r.get("description"),
                         groups=",".join(r.get("groups", [])), mitre=",".join((r.get("mitre") or {}).get("id", [])),
                         agent=ag.get("name"), agent_ip=ag.get("ip"), location=a.get("location"),
                         srcip=data.get("srcip") or (data.get("win", {}).get("eventdata", {}) or {}).get("sourceIp") if isinstance(data, dict) else None,
                         srcuser=data.get("srcuser") or data.get("dstuser") if isinstance(data, dict) else None,
                         full_log=(a.get("full_log") or "")[:400], raw=line if r.get("level", 0) >= 10 else None))
w = pd.DataFrame(rows).drop_duplicates(subset=["id", "ts", "rule_id"])
w["ts"] = pd.to_datetime(w.ts, utc=True, format="ISO8601").dt.tz_convert("America/Los_Angeles")
w.to_pickle(OUT / "wazuh.pkl"); print("wazuh", len(w), "unparsed", bad, w.ts.min(), w.ts.max())

# ---- Pi-hole query log (optional; CSV from pihole-FTL sqlite3, see docs/collection.md)
for f in glob.glob(str(D / "pihole/*.csv*")):
    q = pd.read_csv(f, header=None, names=["ts", "type", "status", "domain", "client", "reply"], dtype={"domain": str, "client": str})
    if str(q.ts.iloc[0]) == "timestamp":   # exported with -header
        q = q.iloc[1:].astype({"ts": float, "type": int, "status": int, "reply": int})
    q["t"] = pd.to_datetime(q.ts, unit="s", utc=True).dt.tz_convert("America/Los_Angeles")
    q["domain"] = q.domain.str.lower().str.rstrip(".")
    q.to_pickle(OUT / "dns.pkl"); print("dns", len(q), q.t.min(), q.t.max())
