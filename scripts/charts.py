"""Render the report's charts from the parsed DataFrames (see parse.py).

Usage: python scripts/charts.py <parsed-dir> <out-dir>
Only aggregate counts, dates, rule names and agent names reach the images.
"""
import sys
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.dates as mdates
import matplotlib.pyplot as plt
import pandas as pd

D, OUT = Path(sys.argv[1]), Path(sys.argv[2])
OUT.mkdir(parents=True, exist_ok=True)

SURFACE, INK, INK2, MUTED, GRID = "#fcfcfb", "#0b0b0b", "#52514e", "#8a8984", "#e6e5e0"
BLUE, ORANGE = "#2a78d6", "#eb6834"
plt.rcParams.update({
    "figure.facecolor": SURFACE, "axes.facecolor": SURFACE, "savefig.facecolor": SURFACE,
    "font.family": "DejaVu Sans", "font.size": 10, "text.color": INK, "axes.labelcolor": INK2,
    "xtick.color": INK2, "ytick.color": INK2, "axes.edgecolor": GRID,
})

w = pd.read_pickle(D / "wazuh.pkl")
s = pd.read_pickle(D / "suricata.pkl")
days = pd.date_range("2026-10-03", "2026-10-18", freq="D")


def strip(ax):
    for side in ("top", "right", "left"):
        ax.spines[side].set_visible(False)
    ax.tick_params(axis="y", length=0)


# 1. Rule-ID collision: when each rule set fired, per day
vw = w[w.desc.str.startswith("Vaultwarden", na=False)]
pt = w[w.rule_id.str.match(r"^1002\d\d$", na=False) & ~w.desc.str.startswith("Vaultwarden", na=False)]
rows = [("Vaultwarden rules\n(100201, 100202, 100213, 100220)", vw, ORANGE),
        ("Purple-Team rules\n(100201–100222)", pt, BLUE)]
fig, ax = plt.subplots(figsize=(9, 2.9))
for y, (label, df, color) in enumerate(rows):
    local = df.ts.dt.tz_localize(None)
    g = df.groupby(local.dt.normalize())
    count = g.size()
    first = count.index + pd.Timedelta(hours=12)  # one dot per day, centred on the day
    ax.scatter(first, [y] * len(first), s=90, color=color, edgecolor=SURFACE, linewidth=2, zorder=3)
    for t, n in zip(first, count):
        ax.annotate(f"{n:,}", (t, y), xytext=(0, 10), textcoords="offset points", ha="center", fontsize=8, color=INK2)
vw_last = vw.ts.max().tz_localize(None); pt_first = pt.ts.min().tz_localize(None)
ax.axvspan(pd.Timestamp("2026-10-09"), pd.Timestamp("2026-10-10"), color=GRID, alpha=0.6, zorder=0, linewidth=0)
ax.annotate(f"Oct 9: Vaultwarden rules last fire {vw_last:%H:%M},\nPurple-Team rules first fire {pt_first:%H:%M}",
            (pd.Timestamp("2026-10-10"), 1.62), xytext=(6, 0), textcoords="offset points", fontsize=8.5, color=INK2, va="top")
ax.set_yticks([0, 1], [r[0] for r in rows], fontsize=9)
ax.set_ylim(-0.6, 1.7)
ax.set_xlim(days[0] - pd.Timedelta(hours=12), days[-1] + pd.Timedelta(hours=12))
ax.xaxis.set_major_locator(mdates.DayLocator(interval=2)); ax.xaxis.set_major_formatter(mdates.DateFormatter("%b %-d"))
ax.grid(axis="x", color=GRID, linewidth=0.8); ax.set_axisbelow(True); strip(ax)
ax.set_title("Alerts per day from each custom rule set", loc="left", fontsize=11, color=INK, pad=10)
fig.tight_layout(); fig.savefig(OUT / "rule-id-collision.png", dpi=160); plt.close(fig)

# 2. Agent coverage: alerts per agent per day (presence strip)
agents = ["kevin-ai", "nexus-ai", "pi-hole", "WIN11-LAB", "win11-lab", "kali-lab"]
fig, ax = plt.subplots(figsize=(9, 3.1))
for y, a in enumerate(agents):
    per_day = w[w.agent == a].groupby(w.ts.dt.tz_localize(None).dt.normalize()).size().reindex(days, fill_value=0)
    on = per_day[per_day > 0]
    ax.scatter(on.index, [y] * len(on), s=70, color=BLUE, edgecolor=SURFACE, linewidth=2, zorder=3, marker="s")
    off = per_day[per_day == 0]
    ax.scatter(off.index, [y] * len(off), s=40, facecolor="none", edgecolor=MUTED, linewidth=1, zorder=2, marker="s")
last = w[w.agent == "kali-lab"].ts.max().tz_localize(None)
y = agents.index("kali-lab")
ax.annotate(f"no events since {last:%b %-d, %H:%M}", (pd.Timestamp("2026-10-12"), y), xytext=(-8, -17),
            textcoords="offset points", fontsize=8.5, color=INK2)
ax.set_yticks(range(len(agents)), agents, fontsize=9); ax.set_ylim(len(agents) + 0.05, -0.7)
ax.set_xlim(days[0] - pd.Timedelta(hours=12), days[-1] + pd.Timedelta(hours=12))
ax.xaxis.set_major_locator(mdates.DayLocator(interval=2)); ax.xaxis.set_major_formatter(mdates.DateFormatter("%b %-d"))
ax.grid(axis="x", color=GRID, linewidth=0.8); ax.set_axisbelow(True); strip(ax)
ax.set_title("Wazuh alerts received per agent, by day", loc="left", fontsize=11, color=INK, pad=22)
from matplotlib.lines import Line2D
ax.legend(handles=[Line2D([], [], marker="s", linestyle="", markersize=8, color=BLUE, label="alerts received"),
                   Line2D([], [], marker="s", linestyle="", markersize=7, markerfacecolor="none", markeredgecolor=MUTED, label="no alerts")],
          loc="lower left", bbox_to_anchor=(0, 1.0), ncol=2, frameon=False, fontsize=9, borderaxespad=0.2)
fig.tight_layout(); fig.savefig(OUT / "agent-coverage.png", dpi=160); plt.close(fig)

# 3. What Suricata actually alerted on
total = len(s)
groups = {
    "Stream: packet out of window": s.sid.eq(2210020).sum(),
    "Stream: invalid ack (2 rules)": s.sid.isin([2210045, 2210029]).sum(),
    "Stream: invalid timestamp": s.sid.eq(2210044).sum(),
    "Other stream / decoder events": (~s.sid.isin([2210020, 2210045, 2210029, 2210044]) & s.sig.str.startswith("SURICATA")).sum(),
    "ET threat signatures": (~s.sig.str.startswith("SURICATA")).sum(),
}
labels, vals = list(groups), list(groups.values())
fig, ax = plt.subplots(figsize=(9, 2.9))
bars = ax.barh(range(len(vals)), vals, color=[BLUE] * (len(vals) - 1) + [ORANGE], height=0.62)
for i, v in enumerate(vals):
    ax.annotate(f"{v:,}  ({v / total:.2%})" if v / total >= 0.0001 else f"{v:,}  (<0.01%)", (v, i), xytext=(6, 0),
                textcoords="offset points", va="center", fontsize=9, color=INK)
ax.set_yticks(range(len(vals)), labels, fontsize=9); ax.invert_yaxis()
ax.set_xlim(0, max(vals) * 1.32); ax.xaxis.set_major_formatter(matplotlib.ticker.FuncFormatter(lambda x, _: f"{x / 1000:.0f}k"))
ax.grid(axis="x", color=GRID, linewidth=0.8); ax.set_axisbelow(True); strip(ax)
ax.set_title(f"Suricata alerts, Sep 26 – Oct 18 ({total:,} total)", loc="left", fontsize=11, color=INK, pad=10)
fig.tight_layout(); fig.savefig(OUT / "suricata-composition.png", dpi=160); plt.close(fig)
print("ok")
