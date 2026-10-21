#!/usr/bin/env python3
"""Risk-based triage for scanner findings.

Reads Trivy JSON (dependency CVEs), SARIF (Semgrep, Gitleaks) and ZAP JSON, enriches CVEs with
EPSS (exploit probability, FIRST.org) and CISA KEV (known exploited), and ranks everything:

  P1  CVE is in CISA KEV, or a secret was found           fix within 48 hours
  P2  EPSS >= 0.10, or CVSS >= 9.0                         fix within 7 days
  P3  CVSS >= 7.0, or a high-severity SAST/DAST finding    fix within 30 days
  P4  everything else                                      backlog, review monthly

Findings listed in triage/accepted.json (rule or CVE id plus a reason) are marked as accepted
false positives instead of disappearing, so the decision stays auditable.

Usage:
  python3 prioritize.py --trivy trivy.json --sarif semgrep.sarif gitleaks.sarif --zap zap.json \
      [--offline fixtures/] [--out report.md] [--fail-on P1]
"""
import argparse
import json
import sys
import urllib.request
from pathlib import Path

EPSS_URL = "https://api.first.org/data/v1/epss?cve={}"
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
SLA = {"P1": "48 hours", "P2": "7 days", "P3": "30 days", "P4": "backlog"}


def fetch_json(url):
    req = urllib.request.Request(url, headers={"User-Agent": "appsec-pipeline-lab"})
    with urllib.request.urlopen(req, timeout=30) as r:
        return json.load(r)


def load_trivy(path):
    data = json.loads(Path(path).read_text())
    out = []
    for result in data.get("Results", []):
        for v in result.get("Vulnerabilities") or []:
            scores = [s.get("V3Score") for s in (v.get("CVSS") or {}).values() if s.get("V3Score")]
            out.append({
                "id": v["VulnerabilityID"], "source": "trivy", "kind": "dependency",
                "title": f"{v.get('PkgName')} {v.get('InstalledVersion')}: {v.get('Title', '')}".strip(),
                "location": result.get("Target", ""), "severity": v.get("Severity", "UNKNOWN"),
                "cvss": max(scores) if scores else None, "fix": v.get("FixedVersion", ""),
            })
    return out


def load_sarif(path):
    data = json.loads(Path(path).read_text())
    out = []
    for run in data.get("runs", []):
        tool = run.get("tool", {}).get("driver", {}).get("name", "sarif").lower()
        for r in run.get("results", []):
            loc = (r.get("locations") or [{}])[0].get("physicalLocation", {})
            where = f"{loc.get('artifactLocation', {}).get('uri', '')}:{loc.get('region', {}).get('startLine', '')}"
            level = r.get("level", "warning")
            out.append({
                "id": r.get("ruleId", "unknown"), "source": tool,
                "kind": "secret" if "gitleaks" in tool else ("dast" if "zap" in tool else "sast"),
                "title": r.get("message", {}).get("text", "")[:120], "location": where,
                "severity": {"error": "HIGH", "warning": "MEDIUM", "note": "LOW"}.get(level, "MEDIUM"),
                "cvss": None, "fix": "",
            })
    return out


def load_zap(path):
    """ZAP baseline/full scan JSON report (zap-baseline.py -J)."""
    data = json.loads(Path(path).read_text())
    risk = {"3": "HIGH", "2": "MEDIUM", "1": "LOW", "0": "LOW"}
    out = []
    for site in data.get("site", []):
        for a in site.get("alerts", []):
            inst = (a.get("instances") or [{}])[0]
            out.append({
                "id": f"ZAP-{a.get('pluginid', '?')}", "source": "zap", "kind": "dast",
                "title": a.get("alert", a.get("name", ""))[:120], "location": inst.get("uri", site.get("@name", "")),
                "severity": risk.get(str(a.get("riskcode", "1")), "LOW"), "cvss": None, "fix": "",
            })
    return out


def enrich(findings, offline_dir=None):
    cves = sorted({f["id"] for f in findings if f["id"].startswith("CVE-")})
    if offline_dir:
        epss_data = json.loads((Path(offline_dir) / "epss.json").read_text())
        kev_data = json.loads((Path(offline_dir) / "kev.json").read_text())
    else:
        epss_data = {"data": []}
        for i in range(0, len(cves), 50):  # the EPSS API accepts batches
            epss_data["data"] += fetch_json(EPSS_URL.format(",".join(cves[i:i + 50]))).get("data", [])
        kev_data = fetch_json(KEV_URL) if cves else {"vulnerabilities": []}
    epss = {d["cve"]: float(d["epss"]) for d in epss_data.get("data", [])}
    kev = {v["cveID"] for v in kev_data.get("vulnerabilities", [])}
    for f in findings:
        f["epss"] = epss.get(f["id"])
        f["kev"] = f["id"] in kev
    return findings


def priority(f):
    cvss = f.get("cvss") or 0
    if f["kev"] or f["kind"] == "secret":
        return "P1"
    if (f.get("epss") or 0) >= 0.10 or cvss >= 9.0:
        return "P2"
    if cvss >= 7.0 or f["severity"] in ("HIGH", "CRITICAL"):
        return "P3"
    return "P4"


def triage(findings, accepted):
    for f in findings:
        f["priority"] = priority(f)
        f["accepted"] = accepted.get(f["id"])
    order = {"P1": 0, "P2": 1, "P3": 2, "P4": 3}
    return sorted(findings, key=lambda f: (f["accepted"] is not None, order[f["priority"]],
                                           -(f.get("epss") or 0), -(f.get("cvss") or 0)))


def render(findings):
    open_ = [f for f in findings if not f["accepted"]]
    counts = {p: sum(1 for f in open_ if f["priority"] == p) for p in SLA}
    lines = ["# Security triage report", "",
             " | ".join(f"**{p}**: {n} (fix within {SLA[p]})" for p, n in counts.items()), "",
             "| Priority | ID | Source | KEV | EPSS | CVSS | Finding | Location | Fix |",
             "|---|---|---|---|---|---|---|---|---|"]
    for f in findings:
        pr = f"{f['priority']} (accepted: {f['accepted']})" if f["accepted"] else f["priority"]
        epss = f"{f['epss']:.3f}" if f.get("epss") is not None else ""
        cvss = f"{f['cvss']:.1f}" if f.get("cvss") else ""
        lines.append(f"| {pr} | {f['id']} | {f['source']} | {'yes' if f['kev'] else ''} | {epss} | {cvss} | "
                     f"{f['title'].replace('|', '/')} | {f['location']} | {f['fix']} |")
    return "\n".join(lines) + "\n"


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--trivy", nargs="*", default=[])
    ap.add_argument("--sarif", nargs="*", default=[])
    ap.add_argument("--zap", nargs="*", default=[])
    ap.add_argument("--accepted", default=str(Path(__file__).with_name("accepted.json")))
    ap.add_argument("--offline", help="directory with epss.json and kev.json instead of calling the APIs")
    ap.add_argument("--out", default="triage-report.md")
    ap.add_argument("--fail-on", choices=["P1", "P2", "P3"], help="exit 1 if an open finding has this priority or higher")
    args = ap.parse_args(argv)

    findings = ([f for p in args.trivy for f in load_trivy(p)] + [f for p in args.sarif for f in load_sarif(p)]
                + [f for p in args.zap for f in load_zap(p)])
    accepted = json.loads(Path(args.accepted).read_text()) if Path(args.accepted).exists() else {}
    findings = triage(enrich(findings, args.offline), accepted)
    Path(args.out).write_text(render(findings))
    print(f"{len(findings)} findings -> {args.out}")

    if args.fail_on:
        limit = ["P1", "P2", "P3"].index(args.fail_on)
        blocking = [f for f in findings if not f["accepted"] and ["P1", "P2", "P3", "P4"].index(f["priority"]) <= limit]
        if blocking:
            print(f"{len(blocking)} open finding(s) at {args.fail_on} or higher: failing the pipeline")
            return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
