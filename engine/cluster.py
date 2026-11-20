"""Clustering of repeated error occurrences for stacktrace-forge.

Turns a paste of many occurrences into a frequency-ranked picture: which
signature dominates, whether the tail is noise, and whether many different
symptoms share one origin frame.
"""

import re
from typing import Any, Dict, List

from . import parsers
from .taxonomy import match_category


def normalize_signature(error: parsers.ParsedError) -> str:
    """Collapse volatile parts of an error into a stable signature."""
    msg = "%s: %s" % (error.error_type, error.message)
    msg = re.sub(r"0x[0-9a-fA-F]+", "0xX", msg)
    msg = re.sub(r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b", "UUID", msg)
    msg = re.sub(r"\b\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}\S*", "TS", msg)
    msg = re.sub(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", "IP", msg)
    msg = re.sub(r"\b\d+\b", "N", msg)
    msg = re.sub(r"'[^']*'", "'S'", msg)
    msg = re.sub(r'"[^"]*"', '"S"', msg)
    msg = re.sub(r"[\w./\\-]+\.(py|js|ts|tsx|jsx|java|cs|go|rb|php|rs|kt|scala)", "FILE", msg)
    msg = re.sub(r"[\w./\\-]+:\d+", "LOC", msg)
    msg = re.sub(r"\s+", " ", msg).strip().lower()
    return msg[:180]


def _origin_frame(error: parsers.ParsedError):
    for f in error.frames:
        if f.in_app:
            return f
    return error.frames[0] if error.frames else None


def cluster_occurrences(text: str, language: str = "auto") -> Dict[str, Any]:
    """Group the pasted occurrences into error clusters and profile the distribution."""
    blocks = parsers.split_occurrences(text)
    parsed: List[parsers.ParsedError] = []
    for b in blocks:
        chain = parsers.parse_error_block(b, language)
        if not chain:
            continue
        # One occurrence is one failure, so cluster on the root cause of the chain
        # rather than on every link in it.
        primary = chain[-1]
        if primary.chain_marker == "Suppressed" and len(chain) > 1:
            primary = chain[-2]
        parsed.append(primary)

    clusters: Dict[str, Dict[str, Any]] = {}
    total = 0
    for err in parsed:
        sig = normalize_signature(err)
        total += 1
        if sig not in clusters:
            cat = match_category(err.headline)
            clusters[sig] = {
                "signature": sig,
                "label": err.headline[:160],
                "error_type": err.error_type,
                "language": err.language,
                "count": 0,
                "category": cat["id"],
                "category_label": cat["label"],
                "severity": cat["severity"],
                "origin": None,
                "locations": [],
                "timestamps": [],
                "samples": [],
            }
        c = clusters[sig]
        c["count"] += 1
        if len(c["samples"]) < 3:
            c["samples"].append(err.headline[:300])
        frame = _origin_frame(err)
        if frame is not None:
            loc = frame.location
            if loc not in c["locations"]:
                c["locations"].append(loc)
            if c["origin"] is None and frame.in_app:
                c["origin"] = loc
        for entry in parsers.parse_logs(err.raw):
            if entry.timestamp:
                c["timestamps"].append(entry.timestamp)

    ordered = sorted(clusters.values(), key=lambda c: (-c["count"], c["signature"]))
    for c in ordered:
        c["share"] = round(100.0 * c["count"] / total, 1) if total else 0.0
        if c["timestamps"]:
            c["first_seen"] = c["timestamps"][0]
            c["last_seen"] = c["timestamps"][-1]

    frame_hits: Dict[str, int] = {}
    for c in ordered:
        for loc in c["locations"]:
            frame_hits[loc] = frame_hits.get(loc, 0) + 1
    chokepoints = [
        {"location": loc, "distinct_errors": n}
        for loc, n in sorted(frame_hits.items(), key=lambda kv: -kv[1])
        if n >= 3
    ]

    singletons = sum(1 for c in ordered if c["count"] == 1)
    dominant = ordered[0] if ordered else None
    insights: List[Dict[str, str]] = []
    if dominant and dominant["share"] >= 60:
        insights.append({
            "kind": "dominant",
            "text": "%d of %d occurrences (%.0f%%) share one signature - fix that one first."
                    % (dominant["count"], total, dominant["share"]),
        })
    if len(ordered) > 2 and singletons >= 0.5 * len(ordered):
        insights.append({
            "kind": "long_tail",
            "text": "%d of %d signatures appear exactly once - that tail is probably noise or "
                    "several unrelated bugs. Group them before you start." % (singletons, len(ordered)),
        })
    if chokepoints:
        insights.append({
            "kind": "chokepoint",
            "text": "%d different error signatures pass through %s - one shared chokepoint is "
                    "probably the real fault." % (chokepoints[0]["distinct_errors"], chokepoints[0]["location"]),
        })
    categories = {}
    for c in ordered:
        categories[c["category"]] = categories.get(c["category"], 0) + c["count"]
    if len(categories) > 1:
        top = sorted(categories.items(), key=lambda kv: -kv[1])
        insights.append({
            "kind": "mixed",
            "text": "Occurrences span %d failure classes (%s). Treat them separately until you "
                    "prove otherwise." % (len(categories), ", ".join("%s x%d" % (k, v) for k, v in top[:4])),
        })
    if not insights:
        insights.append({
            "kind": "single",
            "text": "One occurrence, one signature. Nothing to cluster - use the single-error analysis.",
        })

    return {
        "total_occurrences": total,
        "distinct_signatures": len(ordered),
        "clusters": ordered,
        "chokepoints": chokepoints,
        "insights": insights,
        "language": parsed[0].language if parsed else "unknown",
    }
