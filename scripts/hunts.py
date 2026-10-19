"""Run every hunt in the report and write sanitized evidence tables.

Usage: python scripts/hunts.py <parsed-dir> <evidence-dir>
<parsed-dir> is the output of parse.py. Nothing raw is written: every table
goes through sanitize() first (example 10.20.x.x addressing, no usernames).
"""
import json
import re
import sys
from pathlib import Path

import pandas as pd

D, OUT = Path(sys.argv[1]), Path(sys.argv[2])
OUT.mkdir(parents=True, exist_ok=True)
w = pd.read_pickle(D / "wazuh.pkl")
s = pd.read_pickle(D / "suricata.pkl")
f = pd.read_pickle(D / "filter.pkl")

# ---------------------------------------------------------------- sanitizing
# The real addressing plan, host names and user names live in scripts/site.local.json, which is
# gitignored. scripts/site.example.json shows the format with made-up values.
_here = Path(__file__).parent
SITE = json.loads(((_here / "site.local.json") if (_here / "site.local.json").exists() else (_here / "site.example.json")).read_text())
LAN = re.escape(SITE["lan_prefix"])                   # first two octets of the real LAN, e.g. "172.16."
ZONES = SITE["zones"]                                   # real third octet -> published 10.20.x zone
UP = SITE["upstream_octet"]                             # third octet of the upstream (ISP) router network
WORDS = [(r"tail[0-9a-f]{4,}\.ts\.net", "<tailnet>.ts.net"), (r"[A-Za-z0-9._%+-]+@gmail\.com", "owner@example.com")] + \
        [tuple(w) for w in SITE["words"]]
_Z = "|".join(map(re.escape, ZONES))
_REV = ".".join(reversed(SITE["lan_prefix"].strip(".").split(".")))   # "16.172" for reverse-DNS names


def sanitize(v):
    if not isinstance(v, str):
        return v
    v = re.sub(rf"\b{LAN}({_Z})\.(\d{{1,3}})\b", lambda m: f"{ZONES[m[1]]}.{m[2]}", v)
    v = re.sub(rf"\b{LAN}{UP}\.(\d{{1,3}})\b", r"192.0.2.\1", v)                          # upstream (ISP) router network
    v = re.sub(rf"\b(\d{{1,3}})\.({_Z})\.{re.escape(_REV)}\.in-addr\.arpa\b",               # reverse-DNS names
               lambda m: f"{m[1]}." + ".".join(reversed(ZONES[m[2]].split("."))) + ".in-addr.arpa", v)
    v = re.sub(rf"\b(\d{{1,3}})\.{UP}\.{re.escape(_REV)}\.in-addr\.arpa\b", r"\1.2.0.192.in-addr.arpa", v)
    v = re.sub(r"\b100\.(6[4-9]|[7-9]\d|1[01]\d|12[0-7])\.\d{1,3}\.(\d{1,3})\b", r"100.64.0.\2", v)  # Tailscale
    for pat, rep in WORDS:
        v = re.sub(pat, rep, v)
    return v


def save(df, name):
    df = df.copy()
    for c in df.columns:
        if not pd.api.types.is_numeric_dtype(df[c]) and not pd.api.types.is_datetime64_any_dtype(df[c]):
            df[c] = df[c].map(sanitize)
    if not pd.api.types.is_numeric_dtype(df.index) and not pd.api.types.is_datetime64_any_dtype(df.index):
        df.index = df.index.map(sanitize)
    df.to_csv(OUT / f"{name}.csv")
    return df


def ev(raw):
    try:
        return json.loads(raw).get("data", {}).get("win", {}).get("eventdata", {})
    except Exception:
        return {}


ZONE_OF_IFACE = {"igb0": "Servers (LAN)", "igb0.10": "Trusted", "igb0.30": "Gaming & IoT", "igb1": "WAN (upstream router net)",
                 "igb2": "Isolated (igb2)"}
headline = {}

# H1 - custom rule IDs: does every ID map to exactly one detection?
c = w[w.rule_id.str.match(r"^100[1-3]\d\d$", na=False)]
coll = c.groupby(["rule_id", c.desc.str.replace(r" from \S+$| for \S+@\S+.*$|: /opt/\S+$|\(\w+\.exe\)$", "", regex=True)]) \
        .ts.agg(first="min", last="max", alerts="size").reset_index()
dupes = coll.groupby("rule_id").filter(lambda g: g.iloc[:, 1].nunique() > 1)
save(dupes.set_index("rule_id"), "h1_rule_id_collisions")
vw = w[w.desc.str.startswith("Vaultwarden", na=False)]
headline["vaultwarden_last_alert"] = str(vw.ts.max())
headline["purple_team_first_alert"] = str(c[c.desc.str.startswith("T1", na=False)].ts.min())

# H2 - sensor coverage: which agents went quiet, and was it announced?
life = w[w.rule_id.isin(["501", "503", "504", "505", "506"])].sort_values("ts")[["ts", "agent", "rule_id", "desc", "level"]]
save(life.set_index("ts"), "h2_agent_lifecycle")
last = w.groupby("agent").ts.max()
headline["kali_last_alert"] = str(last["kali-lab"])
headline["lifecycle_alert_levels"] = sorted(life.level.unique().tolist())

# H3 - IDS: what is Suricata actually telling us?
sig = s.groupby(["sid", "sig", "prio"]).size().rename("alerts").reset_index().sort_values("alerts", ascending=False)
sig["share"] = (sig.alerts / len(s)).round(6)
save(sig.set_index("sid"), "h3_suricata_signatures")
internal = pd.concat([s.src, s.dst]); internal = internal[internal.str.startswith(SITE["lan_prefix"])]
headline["suricata_alerts"] = len(s)
headline["suricata_internal_addresses"] = sorted(internal.map(sanitize).unique().tolist())
headline["suricata_top4_share"] = round(s.sid.isin([2210020, 2210045, 2210029, 2210044]).mean(), 4)
headline["suricata_checksum_days"] = sorted(map(str, s[s.sig.str.contains("checksum")].ts.dt.date.unique()))

# H4 - segmentation: do restricted zones try to cross, and are they stopped?
blk = f[f.iface != "igb1"].copy()
blk["zone"] = blk.iface.map(ZONE_OF_IFACE)
blk["kind"] = "default deny"
blk.loc[(blk.rule == "4") & blk.tcpflags.isin(["FA", "RA", "R", "FPA", "PA", "A"]), "kind"] = "default deny (stale TCP state)"
blk.loc[blk.rule != "4", "kind"] = "explicit block rule " + blk.rule
seg = blk.groupby(["zone", "kind", "src", "dst", "proto", "dport"]).size().rename("blocks").reset_index().sort_values("blocks", ascending=False)
save(seg.head(60).set_index("zone"), "h4_internal_blocks")
headline["firewall_window"] = [str(f.ts.min()), str(f.ts.max())]

# H5 - assets outside the firewall (upstream router network seen on WAN)
wan = f[(f.iface == "igb1") & f.src.str.startswith(SITE["lan_prefix"] + UP + ".")]
up = wan.groupby("src").agg(packets=("ts", "size"), ports=("dport", lambda p: " ".join(sorted(set(p.dropna()), key=int)))).reset_index()
save(up.set_index("src"), "h5_upstream_hosts")
roam = f[(f.iface == "igb0") & f.src.str.startswith(SITE["lan_prefix"] + UP + ".")][["ts", "src", "dst", "dport", "tcpflags", "rule"]]
save(roam.set_index("ts"), "h5_upstream_address_on_server_lan")

# H6 - "possible process injection" (Sysmon 10 -> Wazuh 92910): what access was requested?
INJECT = 0x2 | 0x8 | 0x20   # CREATE_THREAD | VM_OPERATION | VM_WRITE
hi = w[w.rule_id == "92910"].copy()
hi["ev"] = hi.raw.map(ev)
hi["source"] = hi.ev.map(lambda e: re.sub(r"^.*\\\\", "", e.get("sourceImage", "")))
hi["mask"] = hi.ev.map(lambda e: e.get("grantedAccess"))
hi["injection_rights"] = hi["mask"].map(lambda m: bool(int(m, 16) & INJECT) if m else None)
inj = hi.groupby(["source", "mask", "injection_rights"]).size().rename("alerts").reset_index().sort_values("alerts", ascending=False)
save(inj.set_index("source"), "h6_process_access_masks")
headline["sysmon_92910_alerts"] = len(hi)
headline["sysmon_92910_with_injection_rights"] = int(hi.injection_rights.sum())

# H7 - custom audit rules: who triggers them?
rows = []
for rid in ["100202", "100205", "100207"]:
    x = w[w.rule_id == rid]
    exe = x.full_log.str.extract(r'exe="([^"]+)"')[0]
    auid = x.full_log.str.extract(r"\bauid=(\d+)")[0]
    for e, n in exe.value_counts().head(8).items():
        rows.append(dict(rule_id=rid, exe=e, alerts=n, share=round(n / len(x), 4)))
    headline[f"audit_{rid}_total"] = len(x)
    headline[f"audit_{rid}_auid_unset"] = int((auid == "4294967295").sum())
save(pd.DataFrame(rows).set_index("rule_id"), "h7_audit_rule_triggers")
x = w[w.rule_id == "100202"]; exe = x.full_log.str.extract(r'exe="([^"]+)"')[0]
headline["audit_100202_wazuh_self"] = int(exe.isin(["/var/ossec/bin/wazuh-syscheckd", "/var/ossec/bin/wazuh-modulesd"]).sum())
headline["audit_100202_tunable"] = int(exe.isin(["/var/ossec/bin/wazuh-syscheckd", "/var/ossec/bin/wazuh-modulesd", "/usr/lib/polkit-1/polkitd"]).sum())

# H8 - every level >= 10 alert, grouped for triage
top = w[w.level >= 10].groupby(["level", "rule_id", "agent", w.desc.str.slice(0, 110)]).size().rename("alerts").reset_index() \
       .sort_values("alerts", ascending=False)
save(top.head(50).set_index("rule_id"), "h8_high_severity_top50")
headline["wazuh_alerts"] = len(w)
headline["wazuh_level10plus"] = int((w.level >= 10).sum())
headline["wazuh_window"] = [str(w.ts.min()), str(w.ts.max())]

# H9 - hardening drift and vulnerabilities
sca = w[w.rule_id.isin(["19003", "19004", "19005", "19010", "19011"])][["ts", "agent", "rule_id", "desc"]]
save(sca.sort_values("ts").set_index("ts"), "h9_sca_changes")
vul = w[w.rule_id.isin(["23503", "23504", "23505", "23506"])]
vt = vul.groupby(["agent", "rule_id", vul.desc.str.extract(r"affects (\S+)")[0].rename("package")]).size().rename("alerts").reset_index()
save(vt.sort_values("alerts", ascending=False).set_index("agent"), "h9_vulnerable_packages")

# H10 - DNS (Pi-hole): forced-DNS coverage, beaconing, DGA/tunneling, bypass paths, risky lookups
import numpy as np
if (D / "dns.pkl").exists():
    q = pd.read_pickle(D / "dns.pkl")
    zone_of = lambda ip: {"1": "Servers", "10": "Trusted", "30": "Gaming & IoT", "40": "Lab", "55": "Guest", "60": "Isolated (igb2)"}.get(
        (re.match(r"192\.168\.(\d+)\.", ip) or [None, "local"])[1], "Pi-hole itself")
    q["zone"] = q.client.map(zone_of)
    headline["dns_lookups"] = len(q); headline["dns_window"] = [str(q.t.min()), str(q.t.max())]
    save(q.groupby("zone").agg(clients=("client", "nunique"), lookups=("t", "size")).sort_values("lookups", ascending=False), "h10_dns_zones")

    # beaconing: (client, domain) pairs with >= 30 lookups over >= 1 day; bursts within 2 s collapsed
    rows = []
    for (c, d), g in q.groupby(["client", "domain"]):
        if len(g) < 30:
            continue
        ts = g.t.sort_values().astype("int64").values / 1e9
        ts = ts[np.r_[True, np.diff(ts) > 2]]
        if len(ts) < 30 or (ts[-1] - ts[0]) < 86400:
            continue
        dt = np.diff(ts); med = float(np.median(dt))
        rows.append(dict(zone=zone_of(c), client=c, domain=d, lookups=len(ts), period_s=round(med), jitter=round(float(np.median(np.abs(dt - med)) / med), 3)))
    b = pd.DataFrame(rows)
    regular = b[b.jitter <= 0.1]
    headline["dns_pairs_analysed"] = len(b); headline["dns_regular_pairs"] = len(regular)
    # personal devices (Trusted, Guest) are summarized, not listed: their app mix is nobody's business
    pub = regular[~regular.zone.isin(["Trusted", "Guest", "Isolated (igb2)"])].sort_values("lookups", ascending=False)
    pub = pd.concat([pub, pd.DataFrame([dict(zone="Trusted + Guest", client="(personal devices, summarized)", domain=f"{(regular.zone.isin(['Trusted', 'Guest'])).sum()} regular pairs: app telemetry, location sharing, Brave/Chrome updaters, WPAD",
                                              lookups=int(regular[regular.zone.isin(["Trusted", "Guest"])].lookups.sum()), period_s=None, jitter=None)])])
    save(pub.set_index("zone"), "h10_dns_regular_lookups")

    # encrypted-DNS and bypass indicators
    STATUS = {1: "blocked (gravity)", 2: "forwarded", 3: "cached", 16: "special domain (blocked by Pi-hole)", 17: "cached (stale)"}
    REPLY = {1: "NODATA", 2: "NXDOMAIN", 3: "CNAME", 4: "IP", 13: "BLOB"}
    enc = q[q.domain.isin(["mask.icloud.com", "mask-h2.icloud.com", "_dns.resolver.arpa", "cloudflare-dns.com", "doh.dns.apple.com", "dns.google",
                           "mozilla.cloudflare-dns.com", "use-application-dns.net", "dns.quad9.net"])]
    save(enc.assign(status=enc.status.map(STATUS), reply=enc.reply.map(REPLY)).groupby(["domain", "zone", "status", "reply"]).size().rename("lookups").reset_index().set_index("domain"),
         "h10_dns_encrypted_dns")
    wp = q[q.domain.str.startswith("wpad.")]
    save(wp.assign(reply=wp.reply.map(REPLY)).groupby(["domain", "zone", "reply"]).size().rename("lookups").reset_index().set_index("domain"), "h10_dns_wpad")

    # infrastructure hosts used for web browsing
    BROWSE = r"(^|\.)(brave\.com|chatgpt\.com|claude\.ai|youtube\.com|google\.com|bing\.com|msn\.com|reddit\.com|geeksforgeeks\.org|netgate\.com|downdetector\.com)$"
    infra = SITE["infra"]                     # real address -> host label
    br = [dict(host=n, lookups=int((q.client == ip).sum()), web_browsing_lookups=int(((q.client == ip) & q.domain.str.contains(BROWSE, regex=True)).sum()))
          for ip, n in infra.items()]
    br = pd.DataFrame(br); br["share"] = (br.web_browsing_lookups / br.lookups).round(3)
    save(br.set_index("host"), "h10_dns_infrastructure_browsing")
    blk = q[q.status.isin([1, 4, 5, 9, 10, 11]) & q.zone.isin(["Servers"])]
    save(blk.groupby(["client", "domain"]).size().rename("blocked").reset_index().sort_values("blocked", ascending=False).set_index("client"), "h10_dns_server_blocked")

    # DGA / tunneling shape
    from collections import Counter
    import math
    ent = lambda s: -sum(v / len(s) * math.log2(v / len(s)) for v in Counter(s).values())
    two = lambda d: ".".join(d.split(".")[-2:])
    left = q.domain.str.split(".").str[0]
    he = q[(left.str.len() >= 12) & left.map(ent).gt(3.6) & ~left.str.startswith("_")].drop_duplicates("domain")
    tun = q.groupby(q.domain.map(two)).agg(unique_subdomains=("domain", "nunique"), avg_length=("domain", lambda x: round(x.str.len().mean(), 1)),
                                           txt_share=("type", lambda x: round((x == 7).mean(), 3)), lookups=("t", "size"))
    # published table covers infrastructure + IoT hosts only; personal devices are counted in headline.json
    nonpersonal = ~q.zone.isin(["Trusted", "Guest"])
    he_np = he[he.zone.isin(q[nonpersonal].zone.unique())]
    tun_np = q[nonpersonal].groupby(q[nonpersonal].domain.map(two)).agg(unique_subdomains=("domain", "nunique"),
             avg_length=("domain", lambda x: round(x.str.len().mean(), 1)), txt_share=("type", lambda x: round((x == 7).mean(), 3)), lookups=("t", "size"))
    save(pd.concat([he_np.domain.map(two).value_counts().rename("high_entropy_names").head(15), tun_np.sort_values("unique_subdomains", ascending=False).head(15)], axis=1),
         "h10_dns_dga_tunneling_shape")
    headline["dns_high_entropy_parents_top5_housewide"] = he.domain.map(two).value_counts().head(5).index.map(lambda d: "CDN" if d not in ("azure.com", "amazonaws.com", "cloudfront.net") else d).tolist()
    headline["dns_high_entropy_names"] = len(he); headline["dns_txt_heavy_domains"] = int(((tun.txt_share > 0.3) & (tun.lookups >= 10)).sum())

(OUT / "headline.json").write_text(json.dumps({k: sanitize(v) if isinstance(v, str) else v for k, v in headline.items()}, indent=2, default=str))
print(json.dumps(headline, indent=2, default=str))
