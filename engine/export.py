"""Export formats for stacktrace-forge: Markdown report, JSON and CSV."""

import csv
import io
import json
from typing import Any, Dict

FENCE = "~~~"


def _sev_marker(sev: str) -> str:
    return {"critical": "CRITICAL", "high": "HIGH", "medium": "MEDIUM", "low": "LOW"}.get(sev, "MEDIUM")


def to_markdown(result: Dict[str, Any]) -> str:
    sc = result["scorecard"]
    lines: list = []
    lines.append("# stacktrace-forge triage report")
    lines.append("")
    meta = result["meta"]
    lines.append("- Language: %s" % meta.get("language", "unknown"))
    lines.append("- Occurrences parsed: %d" % meta.get("occurrence_count", 0))
    lines.append("- Profile: %s" % sc.get("profile_label", sc.get("profile", "general")))
    lines.append("- Score: **%s / 100** (%s)" % (sc.get("overall", 0), sc.get("verdict", "")))
    lines.append("")

    primary = result.get("primary")
    if primary:
        lines.append("## Failure")
        lines.append("")
        lines.append("**%s**" % primary.get("headline", ""))
        lines.append("")
        lines.append("- Type: %s" % primary.get("error_type", ""))
        lines.append("- Message: %s" % primary.get("message", ""))
        lines.append("- Chain depth: %s" % primary.get("chain_length", 1))
        if primary.get("origin_frame"):
            of = primary["origin_frame"]
            lines.append("- Origin frame: %s (%s)" % (of.get("location", ""), of.get("function", "")))
            lines.append("- File: %s" % of.get("file", ""))
        lines.append("")

    cls = result.get("classification", {})
    lines.append("## Classification")
    lines.append("")
    lines.append("- Class: **%s** (%s severity, confidence %s%%)"
                 % (cls.get("label", ""), cls.get("severity", ""), cls.get("confidence", 0)))
    lines.append("- What it means: %s" % cls.get("summary", ""))
    lines.append("")

    lines.append("## Scorecard")
    lines.append("")
    lines.append("| Axis | Score | Weight |")
    lines.append("| --- | ---: | ---: |")
    for axis in sc.get("axes", []):
        lines.append("| %s | %s | %s |" % (axis["label"], axis["score"], axis["weight"]))
    lines.append("")
    lines.append("Verdict: **%s** - %s" % (sc.get("verdict", ""), sc.get("verdict_blurb", "")))
    lines.append("")
    if sc.get("caps"):
        lines.append("Structural caps applied:")
        for c in sc["caps"]:
            lines.append("- %s" % c.get("reason", ""))
        lines.append("")

    hyps = result.get("hypotheses", [])
    if hyps:
        lines.append("## Ranked hypotheses")
        lines.append("")
        for h in hyps:
            lines.append("%d. **%s** (%s likelihood)" % (h["rank"], h["cause"], h["likelihood"]))
            lines.append("   - Why: %s" % h["why"])
            lines.append("   - Check: %s" % h["check"])
        lines.append("")

    findings = result.get("findings", [])
    if findings:
        lines.append("## Findings")
        lines.append("")
        for f in findings:
            lines.append("### [%s] %s" % (_sev_marker(f["severity"]), f["title"]))
            lines.append("")
            lines.append("- Axis: %s" % f["axis"])
            lines.append("- Evidence: %s" % f["evidence"])
            lines.append("- Why it matters: %s" % f["why_it_matters"])
            lines.append("- Fix: %s" % f["fix"])
            lines.append("")

    triage = result.get("triage", [])
    if triage:
        lines.append("## Triage checklist")
        lines.append("")
        for s in triage:
            lines.append("%d. (%s) **%s**" % (s["step"], s["timebox"], s["action"]))
            lines.append("   - %s" % s["detail"])
        lines.append("")

    repro = result.get("repro", {})
    if repro.get("skeleton"):
        lines.append("## Minimal reproduction")
        lines.append("")
        lines.append("%s%s" % (FENCE, repro.get("language", "")))
        lines.append(repro["skeleton"].rstrip())
        lines.append(FENCE)
        lines.append("")

    mq = result.get("message_quality", {})
    if mq:
        lines.append("## Message quality: %s / 100" % mq.get("score", 0))
        lines.append("")
        for issue in mq.get("issues", []):
            lines.append("- %s" % issue)
        if mq.get("suggested_message"):
            lines.append("")
            lines.append("Suggested message:")
            lines.append("")
            lines.append("%stext" % FENCE)
            lines.append(mq["suggested_message"])
            lines.append(FENCE)
        lines.append("")

    plan = result.get("fix_plan", [])
    if plan:
        lines.append("## Fix plan")
        lines.append("")
        for p in plan:
            gain = (" (about +%s points on %s)" % (p["gain"], p["axis"])) if p.get("gain") else ""
            lines.append("%d. **%s**%s" % (p["rank"], p["title"], gain))
            lines.append("   - %s" % p["detail"])
        lines.append("")

    return "\n".join(lines) + "\n"


def to_json(result: Dict[str, Any]) -> str:
    return json.dumps(result, indent=2, default=str)


def to_csv(result: Dict[str, Any]) -> str:
    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(["kind", "rank", "severity", "axis", "title", "detail"])
    for h in result.get("hypotheses", []):
        writer.writerow(["hypothesis", h["rank"], h["likelihood"], "fix_confidence",
                         h["cause"], h["check"]])
    for f in result.get("findings", []):
        writer.writerow(["finding", "", f["severity"], f["axis"], f["title"], f["fix"]])
    for p in result.get("fix_plan", []):
        writer.writerow(["fix", p["rank"], p.get("severity", ""), p.get("axis", ""),
                         p["title"], p["detail"]])
    return buf.getvalue()
