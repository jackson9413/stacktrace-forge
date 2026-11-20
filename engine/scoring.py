"""Scoring for stacktrace-forge: five axes, structural caps, verdict bands."""

from typing import Any, Dict, List

AXES: List[Dict[str, str]] = [
    {
        "id": "diagnostic_clarity",
        "label": "Diagnostic clarity",
        "desc": "Does the error say what failed, for what, and why - without decoding the type name?",
    },
    {
        "id": "root_cause_localisation",
        "label": "Root-cause localisation",
        "desc": "Can you point at the file and line where the fault originates, past the noise frames?",
    },
    {
        "id": "fix_confidence",
        "label": "Fix confidence",
        "desc": "How likely is the next check to identify the true cause rather than a symptom?",
    },
    {
        "id": "observability",
        "label": "Observability",
        "desc": "Would the logs around this failure let you find it again, and correlate it to a request?",
    },
    {
        "id": "fix_safety",
        "label": "Fix safety",
        "desc": "How risky is the obvious fix - a null guard, or a change to money, data or concurrency?",
    },
]

AXIS_IDS = [a["id"] for a in AXES]

PROFILES: Dict[str, Dict[str, Any]] = {
    "general": {
        "label": "General triage",
        "description": "Balanced weighting for any pasted failure.",
        "weights": {
            "diagnostic_clarity": 0.24,
            "root_cause_localisation": 0.24,
            "fix_confidence": 0.20,
            "observability": 0.16,
            "fix_safety": 0.16,
        },
    },
    "incident": {
        "label": "Live incident",
        "description": "Weights localisation, observability and fix safety for a page that is on fire.",
        "weights": {
            "diagnostic_clarity": 0.14,
            "root_cause_localisation": 0.30,
            "fix_confidence": 0.20,
            "observability": 0.26,
            "fix_safety": 0.10,
        },
    },
    "postmortem": {
        "label": "Postmortem and prevention",
        "description": "Weights clarity and observability: what must change so this never repeats.",
        "weights": {
            "diagnostic_clarity": 0.32,
            "root_cause_localisation": 0.14,
            "fix_confidence": 0.14,
            "observability": 0.30,
            "fix_safety": 0.10,
        },
    },
    "code_review": {
        "label": "Error-handling review",
        "description": "Reviews the failure handling itself: is the message useful, is the fix safe.",
        "weights": {
            "diagnostic_clarity": 0.30,
            "root_cause_localisation": 0.10,
            "fix_confidence": 0.12,
            "observability": 0.24,
            "fix_safety": 0.24,
        },
    },
    "repro": {
        "label": "Reproduction and QA",
        "description": "Weights localisation and confidence: can you turn this into a failing test.",
        "weights": {
            "diagnostic_clarity": 0.24,
            "root_cause_localisation": 0.32,
            "fix_confidence": 0.26,
            "observability": 0.08,
            "fix_safety": 0.10,
        },
    },
    "dependency": {
        "label": "Dependency and build problems",
        "description": "Weights localisation and confidence for classpath, module and version failures.",
        "weights": {
            "diagnostic_clarity": 0.18,
            "root_cause_localisation": 0.28,
            "fix_confidence": 0.32,
            "observability": 0.06,
            "fix_safety": 0.16,
        },
    },
}

SEVERITY_PENALTY = {"critical": 13.0, "high": 7.5, "medium": 4.0, "low": 1.5}
SEVERITY_ORDER = {"critical": 3, "high": 2, "medium": 1, "low": 0}

VERDICT_BANDS = [
    (88, "diagnosable", "The failure is fully localised and the next check will find it."),
    (74, "ready_to_debug", "Enough evidence to work from; a couple of gaps remain."),
    (58, "mostly_actionable", "You can start, but the paste is missing context you will want."),
    (40, "thin_evidence", "The paste is too thin to localise - collect more before changing code."),
    (0, "not_diagnosable", "There is not enough here to act on. Start with the triage checklist."),
]


def verdict_for(score: float) -> Dict[str, str]:
    for threshold, name, blurb in VERDICT_BANDS:
        if score >= threshold:
            return {"verdict": name, "blurb": blurb}
    return {"verdict": "not_diagnosable", "blurb": VERDICT_BANDS[-1][2]}


def score_review(
    axis_scores: Dict[str, float],
    findings: List[Dict[str, Any]],
    profile: str = "general",
    caps: List[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Apply finding penalties and structural caps, then compute the overall score."""
    prof = PROFILES.get(profile) or PROFILES["general"]
    weights = prof["weights"]

    scored = {k: float(axis_scores.get(k, 0.0)) for k in AXIS_IDS}
    applied_caps: List[Dict[str, Any]] = list(caps or [])

    for f in findings:
        axis = f.get("axis")
        if axis not in scored:
            continue
        penalty = SEVERITY_PENALTY.get(f.get("severity", "medium"), 4.0)
        scored[axis] -= penalty

    for c in applied_caps:
        axis = c.get("axis")
        cap = c.get("cap")
        if axis in scored and isinstance(cap, (int, float)):
            scored[axis] = min(scored[axis], float(cap))
        if c.get("overall_cap") is not None:
            c["overall_cap"] = float(c["overall_cap"])

    for k in scored:
        scored[k] = max(0.0, min(100.0, round(scored[k], 1)))

    overall = sum(scored[k] * weights[k] for k in AXIS_IDS)
    overall_cap = None
    for c in applied_caps:
        oc = c.get("overall_cap")
        if oc is not None and (overall_cap is None or oc < overall_cap):
            overall_cap = oc
    if overall_cap is not None:
        overall = min(overall, overall_cap)

    overall = round(max(0.0, min(100.0, overall)), 1)
    verdict = verdict_for(overall)

    axes_out = []
    for a in AXES:
        axes_out.append({
            "id": a["id"],
            "label": a["label"],
            "desc": a["desc"],
            "score": scored[a["id"]],
            "weight": weights[a["id"]],
        })

    return {
        "axes": axes_out,
        "overall": overall,
        "profile": profile,
        "profile_label": prof["label"],
        "weights": weights,
        "caps": applied_caps,
        "verdict": verdict["verdict"],
        "verdict_blurb": verdict["blurb"],
    }
