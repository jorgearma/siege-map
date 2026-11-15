"""
Executive threat report in Markdown, built from the SQLite history.

    docker compose exec backend python -m app.report --days 30 > report.md
    curl "http://localhost:8000/api/export/report.md?range=30d" -o report.md

Everything an attacker typed (usernames, paths, network names) is escaped
before it reaches the document: a report is opened in viewers that render
Markdown and HTML.
"""
import argparse
from datetime import datetime
from typing import Optional

from . import campaigns
from .config import settings
from .db import Database
from .usernames import categorize


def esc(value) -> str:
    """Attacker-controlled text as an inert Markdown code span."""
    text = "".join(c if c.isprintable() else "?" for c in str(value))[:120]
    text = text.replace("`", "'").replace("|", "\\|").replace("<", "&lt;").replace(">", "&gt;")
    return f"`{text}`" if text else "—"


def _table(headers: list[str], rows: list[list]) -> list[str]:
    if not rows:
        return ["_No data in this period._", ""]
    out = ["| " + " | ".join(headers) + " |", "|" + "|".join("---" for _ in headers) + "|"]
    out += ["| " + " | ".join(str(c) for c in row) + " |" for row in rows]
    return out + [""]


def _n(value) -> str:
    return f"{value or 0:,}"


def build_markdown(db: Database, days: Optional[int] = 30) -> str:
    period = f"last {days} days" if days else "all time"
    ips = db.ip_counts()
    attempts = db.total("ssh_attempts", days)
    probes = db.total("source", days, key="http")
    new_ips = db.total("ip_new", days, key="ssh")
    returning = db.total("ip_returning", days, key="ssh")
    found = campaigns.detect(db, limit=15, use_cache=False)
    confident = [c for c in found if c["level"] != "LOW"]
    alerts = db.alerts(limit=200)
    serious = [a for a in alerts if a["severity"] in ("CRITICAL", "HIGH")]
    top_user = db.top("ssh_user", days, 1)
    top_country = db.top("ssh_country", days, 1)

    md = [
        f"# Threat report — {settings.VPS_LABEL}",
        "",
        f"Period: **{period}** · data since {db.first_day() or 'today'} · "
        f"generated {datetime.now().isoformat(timespec='minutes')}",
        "",
        "## Summary",
        "",
        f"- **{_n(attempts)}** SSH authentication attempts from **{_n(new_ips)}** new addresses "
        f"({_n(returning)} address-days of repeat visitors).",
        f"- **{_n(probes)}** hostile HTTP requests (probes and exploit attempts).",
        f"- **{len(confident)}** group(s) of addresses assessed as a probable or coordinated campaign, "
        f"out of {len(found)} that share a wordlist or a target.",
        f"- **{len(serious)}** HIGH/CRITICAL alert(s) on record.",
    ]
    if top_user and top_country:
        md.append(f"- Most targeted account: {esc(top_user[0]['key'])}. "
                  f"Main origin: {esc(top_country[0]['key'])}.")
    md += ["", "## What was targeted (SSH)", ""]
    md += _table(["Account", "Category", "Attempts"],
                 [[esc(u["key"]), categorize(u["key"]), _n(u["count"])] for u in db.top("ssh_user", days, 15)])

    md += ["## Where it came from", ""]
    md += _table(["Country", "SSH lines"], [[esc(r["key"]), _n(r["count"])] for r in db.top("ssh_country", days, 10)])
    md += _table(["Network", "SSH lines"], [[esc(r["key"]), _n(r["count"])] for r in db.top("ssh_org", days, 10)])
    md += _table(["Network type", "SSH lines"], [[esc(r["key"]), _n(r["count"])] for r in db.top("ssh_net", days, 6)])

    md += [
        "## Campaigns", "",
        "A shared wordlist proves a shared tool, not a shared operator. Confidence combines three "
        "independent signals (wordlist rarity, arrival timing, shared network); a group is called "
        "coordinated only when at least two agree.", "",
    ]
    md += _table(
        ["ID", "Verdict", "Confidence", "Addresses", "Attempts", "Targets", "Evidence"],
        [[c["fingerprint"], c["label"], f"{c['confidence']}/100 ({c['level']})", c["ips"],
          _n(c["attempts"]), " ".join(esc(u) for u in c["usernames"][:4]), c["evidence"][0]]
         for c in found],
    )

    md += ["## Persistence", "", f"{_n(ips.get('came_back'))} of {_n(ips.get('total'))} addresses "
           "were seen on more than one day.", ""]
    md += _table(["Address", "Days active", "Attempts", "Country", "Network"],
                 [[p["ip"], p["days_active"], _n(p["attempts"]), esc(p["country"]), esc(p["org"])]
                  for p in db.persistent_ips(10)])
    dual = db.dual_vector(10)
    if dual:
        md += ["Networks seen on both SSH and HTTP (matched by /24, HTTP addresses are stored truncated):", ""]
        md += _table(["Network", "SSH addresses", "SSH attempts", "HTTP requests", "Owner"],
                     [[d["network"], d["ssh_ips"], _n(d["ssh_attempts"]), _n(d["http_hits"]), esc(d["org"])]
                      for d in dual])

    md += ["## Web exploitation attempts", ""]
    sigs = []
    for r in db.top("http_sig", days, 15):
        sig_id, name, product, kind = (r["key"].split("|") + ["", "", ""])[:4]
        sigs.append([esc(sig_id), esc(name), esc(product), kind, _n(r["count"])])
    md += _table(["Signature", "Name", "Product", "Kind", "Requests"], sigs)
    md += _table(["Path probed", "Requests"], [[esc(r["key"]), _n(r["count"])] for r in db.top("http_probe", days, 10)])

    md += ["## Alerts", ""]
    md += _table(["When", "Severity", "Rule", "Alert", "Times seen"],
                 [[a["ts"][:16].replace("T", " "), a["severity"], a["rule"], esc(a["title"]), a["hits"]]
                  for a in serious[:25]])

    md += ["## Daily volume", ""]
    series = db.daily_series("source", min(days or 30, 60))
    md += _table(["Day", "SSH lines", "HTTP probes", "Visits"],
                 [[d["day"], _n(d.get("ssh")), _n(d.get("http")), _n(d.get("visit"))] for d in series])

    md += [
        "## Method and limits", "",
        "- Source: sshd and web server logs of one exposed host. It observes attempts, not intent.",
        "- sshd logs the account that was tried, never the password: attacks are classified by "
        "shape (accounts × tries), and credential stuffing cannot be told apart from guessing.",
        "- HTTP addresses are truncated to /24 (IPv4) or /48 (IPv6) before storage.",
        "- Individual events are kept for a few days; older figures come from daily aggregates.",
        "",
    ]
    return "\n".join(md)


def main() -> None:
    ap = argparse.ArgumentParser(description="Markdown threat report from the siege-map database")
    ap.add_argument("--db", default=settings.DB_PATH)
    ap.add_argument("--days", type=int, default=30, help="0 = all time")
    args = ap.parse_args()
    print(build_markdown(Database(args.db), args.days or None))


if __name__ == "__main__":
    main()
