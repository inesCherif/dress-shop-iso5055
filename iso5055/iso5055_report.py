"""ISO/IEC 5055 view of a SonarQube project.

SonarQube has no ISO 5055 report (SonarSource advises building one from the Web API). This script does that:
1. it finds every SonarQube rule tagged "cwe" for the project's languages and reads the CWE numbers from the rule
   itself (its security standards and the cwe.mitre.org links in its description);
2. it keeps the CWEs listed in ISO/IEC 5055 clause 7 (iso5055-cwes.json, next to this file);
3. it counts the project's open issues raised by those rules, per characteristic, like clause 9 does.

    set SONAR_TOKEN=...            (a user or analysis token, never written in files)
    python iso5055_report.py --project my-key [--url http://localhost:9000] [--json out.json]

Only the Python standard library is used.
Limits: SonarQube is not an ISO 5055 measurement tool. It only reports the CWEs its rules know, so a 0 means
"SonarQube found nothing", not "the code is free of this weakness". The coverage columns show how much it can see.
"""
import argparse, base64, json, os, re, sys, urllib.parse, urllib.request
from pathlib import Path

CHARS = ["Security", "Reliability", "Performance Efficiency", "Maintainability"]


def api(base, token, path, **params):
    url = f"{base}/api/{path}?{urllib.parse.urlencode(params)}"
    req = urllib.request.Request(url)
    req.add_header("Authorization", "Basic " + base64.b64encode(f"{token}:".encode()).decode())
    with urllib.request.urlopen(req) as r:
        return json.load(r)


def pages(base, token, path, key, **params):
    p = 1
    while True:
        d = api(base, token, path, ps=100, p=p, **params)
        yield from d[key]
        if p * 100 >= min(d.get("total", d.get("paging", {}).get("total", 0)), 10000):
            return
        p += 1


def rule_cwes(rule):
    text = json.dumps(rule.get("descriptionSections", [])) + rule.get("htmlDesc", "")
    cwes = set(re.findall(r"cwe\.mitre\.org/data/definitions/(\d+)", text))
    cwes |= {s.split(":")[1] for s in rule.get("securityStandards", []) if s.startswith("cwe:")}
    return cwes


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--project", required=True)
    ap.add_argument("--url", default="http://localhost:9000")
    ap.add_argument("--json", help="also write the full result to this file")
    ap.add_argument("--details", action="store_true", help="also list every issue (file:line, rule, message)")
    a = ap.parse_args()
    token = os.environ.get("SONAR_TOKEN") or sys.exit("Set SONAR_TOKEN first.")
    iso = json.loads((Path(__file__).with_name("iso5055-cwes.json")).read_text(encoding="utf-8"))["cwes"]

    # 1. size, languages and quality profiles of the project
    m = api(a.url, token, "measures/component", component=a.project, metricKeys="ncloc,ncloc_language_distribution")
    meas = {x["metric"]: x.get("value", "") for x in m["component"]["measures"]}
    ncloc = int(meas.get("ncloc", 0))
    langs = [kv.split("=")[0] for kv in meas.get("ncloc_language_distribution", "").split(";") if kv]
    profiles = {p["language"]: p for p in api(a.url, token, "qualityprofiles/search", project=a.project)["profiles"]}

    # 2. rule -> ISO CWEs, for every cwe-tagged rule of these languages; which of them are active in the profile
    rule_iso, exists, active = {}, set(), set()
    for lang in langs:
        prof = profiles.get(lang, {}).get("key")
        on = {r["key"] for r in pages(a.url, token, "rules/search", "rules", languages=lang, tags="cwe", f="name",
                                      activation="true", qprofile=prof)} if prof else set()
        for r in pages(a.url, token, "rules/search", "rules", languages=lang, tags="cwe",
                       f="name,descriptionSections,htmlDesc"):
            hit = sorted(c for c in rule_cwes(r) if c in iso)
            if hit:
                rule_iso[r["key"]] = hit
                exists.update(hit)
                if r["key"] in on:
                    active.update(hit)

    # 3. open issues raised by those rules
    found, total = {}, 0
    for i in pages(a.url, token, "issues/search", "issues", components=a.project, issueStatuses="OPEN,CONFIRMED"):
        total += 1
        for c in rule_iso.get(i["rule"], []):
            found.setdefault(c, []).append({"rule": i["rule"], "file": i["component"].split(":", 1)[-1],
                                            "line": i.get("line"), "message": i["message"]})

    # 4. clause 9: a characteristic's score = number of occurrences of its weaknesses
    rows = []
    for c in CHARS:
        cwes = [k for k, v in iso.items() if c in v["characteristics"]]
        occ = sum(len(found.get(k, [])) for k in cwes)
        rows.append({"characteristic": c, "iso_cwes": len(cwes), "rules_exist": len([k for k in cwes if k in exists]),
                     "rules_active": len([k for k in cwes if k in active]), "occurrences": occ,
                     "per_kloc": round(occ / (ncloc / 1000), 2) if ncloc else None,
                     "cwes_found": sorted({k for k in cwes if found.get(k)}, key=int)})

    print(f"\nISO/IEC 5055 view of '{a.project}'  ({ncloc} lines of code, languages: {', '.join(langs)})")
    print("Quality profile: " + ", ".join(f"{l} = {profiles[l]['name']}" for l in langs if l in profiles))
    n_iso = len({(i['file'], i['line'], i['rule']) for v in found.values() for i in v})
    print(f"Open SonarQube issues: {total}; with an ISO 5055 CWE: {n_iso}\n")
    print(f"{'Characteristic':24}{'ISO CWEs':>9}{'has rule':>10}{'active':>8}{'Found':>7}{'/KLOC':>7}  CWEs found")
    for r in rows:
        print(f"{r['characteristic']:24}{r['iso_cwes']:>9}{r['rules_exist']:>10}{r['rules_active']:>8}{r['occurrences']:>7}"
              f"{r['per_kloc'] if r['per_kloc'] is not None else '-':>7}  {', '.join('CWE-' + k for k in r['cwes_found'])}")
    print("\n'has rule' = ISO CWEs that SonarQube has at least one rule for (these languages); 'active' = turned on in")
    print("your quality profile. One CWE can count in several characteristics (ISO 5055 clause 6.3).")
    for cwe in sorted(found, key=int):
        print(f"\nCWE-{cwe} {iso[cwe]['title']}  ({', '.join(iso[cwe]['characteristics'])}): "
              f"{len(found[cwe])} issues, rules {', '.join(sorted({i['rule'] for i in found[cwe]}))}")
        for i in found[cwe] if a.details else []:
            print(f"  {i['file']}:{i['line']}  [{i['rule']}]  {i['message']}")
    if a.json:
        Path(a.json).write_text(json.dumps({"project": a.project, "ncloc": ncloc, "languages": langs,
                                            "profiles": {l: p["name"] for l, p in profiles.items() if l in langs},
                                            "total_issues": total, "iso_issues": n_iso, "characteristics": rows,
                                            "issues": found, "rule_to_iso_cwe": rule_iso}, indent=1), encoding="utf-8")


if __name__ == "__main__":
    main()
