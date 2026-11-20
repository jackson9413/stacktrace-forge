"""Analysis engine for stacktrace-forge.

Takes a pasted stack trace or log excerpt and returns:
  * the parsed failure and where it originates
  * a classification against the local error taxonomy
  * ranked hypotheses with the check that discriminates between them
  * findings (evidence + why it matters + a concrete fix)
  * a time-boxed triage checklist and a minimal reproduction skeleton
  * a five-axis 0-100 scorecard with structural caps
  * a prioritised fix plan

Pure standard library: no network calls, no LLM.
"""

import re
from typing import Any, Dict, List, Optional, Tuple

from . import parsers
from .scoring import AXIS_IDS, PROFILES, SEVERITY_ORDER, score_review
from .taxonomy import get_category, match_category

VAGUE_RE = re.compile(
    r"(something went wrong|unknown error|internal (?:server )?error|an error occurred|"
    r"unexpected error|error occurred|problem occurred|operation failed|request failed|failed)",
    re.I,
)
GENERIC_TYPES = {
    "error", "exception", "failure", "throwable", "runtimeexception", "systemexception",
    "apptexception", "apiexception", "err",
}
SECRET_LABEL_RE = parsers._SECRET_RE
PII_RE = parsers._PII_RE
CORRELATION_RE = parsers._CORRELATION_RE
TIMEOUT_VALUE_RE = re.compile(r"\b\d+(\.\d+)?\s*(ms|milliseconds?|s|secs?|seconds?|m|minutes?)\b", re.I)
RETRY_RE = re.compile(r"\b(retr(?:y|ies|ying)|redeliver|requeue)\b", re.I)
BACKOFF_RE = re.compile(r"\b(back ?off|jitter|exponential|sleep|delay)\b", re.I)
VALIDATION_RE = re.compile(r"\b(validat\w*|schema|required|pydantic|jsonschema|contract)\b", re.I)
GUARD_RE = re.compile(
    r"(\boptional\b|\bnullable\b|is not None|isn't None|!= null|!== null|\bnull\b\s*check|"
    r"orElse|ifPresent|Optional\.of|safe-?nav|\?\.)",
    re.I,
)
ENV_RE = re.compile(
    r"\b(env|environment|version|release|commit|sha|revision|pod|host|instance|region|zone|"
    r"deploy|build|image tag|staging|production)\b",
    re.I,
)
ID_RE = re.compile(r"(\b\d{2,}\b|\b[A-Za-z_]*[Ii]d\b|\b[a-z_]+_id\b)", re.I)
_CONTEXT_TOKEN_RE = re.compile(
    r"(?i)(\b(?:id|uuid|ref|code)\s*[=:]\s*\S+)"
    r"|(\b(?:order|customer|user|account|tenant|invoice|request|job|batch|ticket|file|row|"
    r"plan|subscription|project|payment|session|profile)\b\s+[\w.#-]+)"
    r"|(\b[a-z_]{2,}_id\b)|(\b[A-Z][a-zA-Z]*Id\b)"
)
_FRAME_START_RE = re.compile(r"^\s*(?:at\s|File \")")


def _level_before_trace(raw: str):
    """The log level of the line immediately above the first stack frame, if any."""
    lines = raw.splitlines()
    for i, line in enumerate(lines):
        if _FRAME_START_RE.match(line):
            for j in range(i - 1, -1, -1):
                if lines[j].strip():
                    m = re.search(r"\b(TRACE|DEBUG|INFO|INFORMATION|NOTICE|WARN|WARNING)\b", lines[j])
                    return m.group(1).upper() if m else None
            return None
    return None


def _finding(rule_id, axis, severity, title, evidence, why, fix) -> Dict[str, Any]:
    return {
        "id": rule_id,
        "axis": axis,
        "severity": severity,
        "title": title,
        "evidence": evidence,
        "why_it_matters": why,
        "fix": fix,
    }


def _match_line(text: str, pattern: str, limit: int = 180) -> str:
    for line in text.splitlines():
        if re.search(pattern, line, re.I):
            return line.strip()[:limit]
    return ""


def _strip_timestamps(text: str) -> str:
    out = text
    for pat in parsers._TS_PATTERNS:
        out = re.sub(pat, " ", out)
    return out


def _origin_frame(error: parsers.ParsedError) -> Optional[parsers.Frame]:
    for f in error.frames:
        if f.in_app:
            return f
    return error.frames[0] if error.frames else None


# ---------------------------------------------------------------------------
# findings rules
# ---------------------------------------------------------------------------


def _rules(ctx: Dict[str, Any]) -> List[Dict[str, Any]]:
    raw = ctx["raw"]
    primary = ctx["primary"]
    msg = primary.message if primary else ""
    etype = (primary.error_type if primary else "") or ""
    frames = primary.frames if primary else []
    logs = ctx["logs"]
    cat_id = ctx["category"]["id"]
    findings: List[Dict[str, Any]] = []

    # 1. vague message
    if msg:
        hit = VAGUE_RE.search(msg)
        if hit and not (hit.group(0).lower() == "failed" and len(msg) > 40):
            findings.append(_finding(
                "vague_message", "diagnostic_clarity", "medium",
                "The error message does not say what failed",
                "Message: %s" % msg[:140],
                "Nobody reading the logs can tell which operation, which input or which reason. "
                "You will end up grepping by timestamp instead of by failure.",
                "Name the operation, the entity and the reason in the message: "
                "'Failed to load invoice 4821 for tenant acme: upstream returned 503'.",
            ))

    # 2. missing error type
    if primary is not None and not etype:
        findings.append(_finding(
            "no_error_type", "diagnostic_clarity", "high",
            "No exception type in the paste",
            "First line: %s" % (raw.splitlines()[0][:140] if raw.splitlines() else ""),
            "Without the type you cannot map the failure to a class of causes, and every "
            "hypothesis stays generic.",
            "Copy the paste starting at the exception header line, not from the first stack frame.",
        ))

    # 3. generic error type
    elif etype.strip().lower() in GENERIC_TYPES:
        findings.append(_finding(
            "generic_error_type", "diagnostic_clarity", "medium",
            "The exception type carries no information",
            "Type: %s" % etype,
            "Error, Exception and RuntimeException are catch-all types, so the type cannot narrow "
            "the cause and readers learn nothing from the log line alone.",
            "Throw the specific type (IllegalArgumentException, EntityNotFoundException) or, if you "
            "must wrap, keep the original as the cause.",
        ))

    # 4. no frames
    if primary is not None and not frames:
        findings.append(_finding(
            "no_frames", "root_cause_localisation", "high",
            "No stack frames in the paste",
            "Occurrences parsed: %d" % len(ctx["errors"]),
            "Without frames there is no file and no line, so the search space is the whole codebase.",
            "Paste the full trace including every frame, and make sure the logging call passes the "
            "exception object rather than its message.",
        ))

    # 5. frames without locations
    elif frames and not any(f.file or f.line for f in frames):
        findings.append(_finding(
            "frames_without_location", "root_cause_localisation", "medium",
            "Frames have no file or line information",
            "First frame: %s" % frames[0].raw[:140],
            "Function names alone usually point at a framework layer, not at your code.",
            "Build with debug symbols (or -g) and paste the trace from a build that includes file and "
            "line information.",
        ))

    # 6. only library frames
    if frames and not any(f.in_app for f in frames):
        findings.append(_finding(
            "library_only_frames", "root_cause_localisation", "medium",
            "Every frame is in a library or framework",
            "Origins: %s" % ", ".join(sorted({f.origin for f in frames})),
            "When the whole trace sits in third-party code the fault is usually configuration, "
            "credentials or environment - not application logic.",
            "Check the configuration the library reads, the credential it authenticates with, and the "
            "version it resolved to.",
        ))

    # 7. swallowed exception
    swallow = None
    for pat in (r"except\s*(?:[A-Za-z_][\w.]*\s*)?:\s*\n?\s*pass\b",
                r"catch\s*\([^)]*\)\s*\{\s*\}",
                r"catch\s*\([^)]*\)\s*\{\s*//[^\n]*\}",
                r"\.catch\s*\(\s*(?:function)?\s*\(?[^)]*\)?\s*=>\s*\{\s*\}",
                r"rescue\s*=>\s*nil"):
        m = re.search(pat, raw)
        if m:
            swallow = m.group(0)
            break
    if swallow:
        findings.append(_finding(
            "swallowed_exception", "fix_confidence", "high",
            "An exception is swallowed somewhere in this path",
            "Snippet: %s" % swallow.replace("\n", " ")[:140],
            "A swallowed exception destroys the evidence: the original failure never reaches the log, "
            "so you are debugging a symptom instead of the cause.",
            "Log the exception with its stack trace before continuing, or rethrow it wrapped with the "
            "original kept as the cause.",
        ))

    # 8. bare except
    if re.search(r"except\s*:", raw) and not swallow:
        findings.append(_finding(
            "bare_except", "fix_confidence", "medium",
            "A bare except swallows every exception, including control flow",
            "Snippet: %s" % _match_line(raw, r"except\s*:"),
            "Bare excepts also catch KeyboardInterrupt and SystemExit, and they hide the difference "
            "between a real fault and a normal exit.",
            "Catch the specific exception classes you expect, and let the rest propagate.",
        ))

    # 9. generic wrapper without cause
    wrap = _match_line(raw, r"(raise|new)\s+[A-Za-z_]*(?:RuntimeError|Exception|Error)\s*\(")
    if wrap and not re.search(r"\bfrom\b|\bcause\b|\binner\b", raw, re.I):
        findings.append(_finding(
            "generic_wrapper", "diagnostic_clarity", "medium",
            "A generic exception is thrown without preserving the cause",
            "Snippet: %s" % wrap[:140],
            "Replacing a specific failure with a generic one loses the type, the message and the "
            "original stack, which is exactly what you need at 2am.",
            "Re-throw the original as the cause (raise ... from e) and keep the specific type.",
        ))

    # 10. deep cause chain
    if len(ctx["chain"]) > 3:
        findings.append(_finding(
            "deep_cause_chain", "root_cause_localisation", "low",
            "The cause chain is deep enough to hide the origin",
            "Chain depth: %d" % len(ctx["chain"]),
            "Each wrapper adds a layer to read before you reach the real failure, and the top of the "
            "trace stops being informative.",
            "Collapse the wrappers: log the root cause once, with the chain, instead of re-wrapping "
            "at every layer.",
        ))

    # 11. error logged without a trace
    error_logs = [e for e in logs if e.level in ("ERROR", "FATAL", "CRITICAL")]
    if error_logs and not frames and ctx["occurrence_count"] <= 1:
        findings.append(_finding(
            "error_without_trace", "observability", "high",
            "An error was logged without its stack trace",
            "Log line: %s" % error_logs[0].raw[:140],
            "A message-only log line tells you that something broke but never where, and the next "
            "occurrence will be just as useless.",
            "Log the exception object (log.error('context', e)) so the trace and the cause chain are "
            "captured.",
        ))

    # 12. trace logged at the wrong level
    if frames and logs:
        wrong_level = _level_before_trace(raw)
        if wrong_level:
            findings.append(_finding(
                "trace_at_wrong_level", "observability", "medium",
                "A stack trace is logged below error level",
                "Level: %s" % wrong_level,
                "Traces at INFO or DEBUG are filtered out by default, so the most expensive log line "
                "is also the one nobody sees.",
                "Log failures at ERROR with context, and keep INFO for lifecycle events.",
            ))

    # 13. no correlation id
    if logs and not any(CORRELATION_RE.search(e.raw) for e in logs):
        findings.append(_finding(
            "no_correlation_id", "observability", "medium",
            "No request or trace id in the log lines",
            "Sampled line: %s" % logs[0].raw[:140],
            "Without a correlation id you cannot pull the lines for one request out of a shared log, "
            "which is the whole job during an incident.",
            "Include a request id in every line (MDC, a structured logger field, or a log prefix) and "
            "echo it back to the caller.",
        ))

    # 14. secret in the log
    secret_hit = SECRET_LABEL_RE.search(raw)
    if secret_hit:
        findings.append(_finding(
            "secret_in_log", "observability", "critical",
            "A credential appears in the pasted output",
            "Snippet: %s" % secret_hit.group(0)[:140],
            "Credentials in logs are copied into ticket systems, chat windows and log aggregators, "
            "and they usually outlive the incident that produced them.",
            "Redact at the logging boundary, rotate the exposed credential, and scrub the log store "
            "where it was written.",
        ))

    # 15. pii in the log
    else:
        pii_probe = _strip_timestamps(raw)
        pii_hit = PII_RE.search(pii_probe)
        if pii_hit:
            findings.append(_finding(
                "pii_in_log", "observability", "high",
                "Personal data appears in the pasted output",
                "Snippet: %s" % pii_hit.group(0)[:140],
                "Customer data in logs leaks into anyone with log access and usually breaks the "
                "organisation's own data handling rules.",
                "Log identifiers instead of personal data, and hash or tokenise the rest.",
            ))

    # 16. missing timestamps
    if logs and not any(e.timestamp for e in logs):
        findings.append(_finding(
            "missing_timestamps", "observability", "medium",
            "Log lines carry no timestamp",
            "Sampled line: %s" % logs[0].raw[:140],
            "Without timestamps you cannot line the failure up with a deploy, a metric spike or "
            "another service's errors.",
            "Log with an ISO-8601 timestamp and timezone on every line.",
        ))

    # 17. unhandled promise rejection
    if re.search(r"unhandled ?promise ?rejection|unhandledrejection", raw, re.I):
        findings.append(_finding(
            "unhandled_promise", "fix_confidence", "high",
            "A promise rejection was never handled",
            "Snippet: %s" % _match_line(raw, r"unhandled ?promise ?rejection", 140),
            "The rejection disappears from the error path, so the operation silently half-completed "
            "and the real failure appears later as missing data.",
            "Await the promise or attach a catch handler that logs and rethrows.",
        ))

    # 18. timeout with no configured value
    if cat_id == "timeout" and not TIMEOUT_VALUE_RE.search(raw):
        findings.append(_finding(
            "missing_timeout_value", "fix_safety", "medium",
            "No timeout value is visible anywhere in the paste",
            "Snippet: %s" % _match_line(raw, r"timeout", 140),
            "You cannot tell whether the budget is too tight or too generous without the number, and "
            "you cannot tell which caller owns it.",
            "Set an explicit timeout on the call, below the caller's own deadline, and log it with "
            "the failure.",
        ))

    # 19. retry with no backoff
    if RETRY_RE.search(raw) and not BACKOFF_RE.search(raw):
        findings.append(_finding(
            "retry_without_backoff", "fix_safety", "medium",
            "Retries are visible but no backoff is",
            "Snippet: %s" % _match_line(raw, r"retr(?:y|ies|ying)", 140),
            "Immediate retries against a struggling dependency turn a small failure into a "
            "self-inflicted outage.",
            "Use exponential backoff with jitter, cap the attempt count, and honour the "
            "Retry-After header.",
        ))

    # 20. no validation around a parse failure
    if cat_id == "bad_data" and not VALIDATION_RE.search(raw):
        findings.append(_finding(
            "missing_input_validation", "fix_safety", "medium",
            "Unvalidated input reached the parser",
            "Snippet: %s" % _match_line(raw, r"(json|parse|deserial)", 140),
            "Every malformed payload becomes an exception, which means untrusted input is choosing "
            "your error path.",
            "Validate the payload against a schema at the boundary and reject it with a clear "
            "400 before it reaches the parser.",
        ))

    # 21. trace leaked to the caller
    if frames and re.search(r"HTTP/1\.[01] \d{3}|Response body|response_body", raw, re.I):
        findings.append(_finding(
            "trace_leaked_to_client", "observability", "high",
            "The stack trace is being returned to the caller",
            "Snippet: %s" % _match_line(raw, r"HTTP/1\.[01] \d{3}|Response body", 140),
            "Returning a trace hands an attacker your package layout, file paths and library "
            "versions, and tells them exactly which frames to target.",
            "Return a correlation id and a generic message, and keep the trace on the server.",
        ))

    # 22. recursive frames
    if frames:
        counts = {}
        for f in frames:
            counts[f.function or f.location] = counts.get(f.function or f.location, 0) + 1
        worst, worst_n = max(counts.items(), key=lambda kv: kv[1])
        if worst_n >= 8:
            findings.append(_finding(
                "recursive_frames", "root_cause_localisation", "medium",
                "The same frame repeats, so the loop is the bug",
                "Frame repeated %d times: %s" % (worst_n, worst[:110]),
                "A repeating frame almost always means unbounded recursion or a cycle in the data, "
                "not a fault at the deepest frame.",
                "Find the cycle: check the base case of the recursion and the visited set on any "
                "graph walk.",
            ))

    # 23. null deref with no visible guard
    if cat_id == "null_reference" and not GUARD_RE.search(raw):
        findings.append(_finding(
            "null_without_guard", "fix_safety", "medium",
            "Nothing in the path guards against the null",
            "Snippet: %s" % _match_line(raw, r"(null|none|undefined)", 140),
            "Adding a null check is the cheap fix but it can also hide the real defect: why was the "
            "value missing in the first place?",
            "Fix the producer of the value as well as the consumer: make the field optional at the "
            "type level, or guarantee it is populated before use.",
        ))

    # 24. no request context
    if msg and not ID_RE.search(msg) and not _CONTEXT_TOKEN_RE.search(raw):
        findings.append(_finding(
            "no_request_context", "diagnostic_clarity", "medium",
            "The message carries no id, value or entity name",
            "Message: %s" % msg[:140],
            "A failure you cannot tie to an input is a failure you cannot reproduce.",
            "Include the identifier that failed (order id, user id, request id, filename) in the "
            "message.",
        ))

    # 25. server blamed for a client error
    if re.search(r"\b50[03]\b", raw) and re.search(r"\b(400|401|403|404|409|422)\b", raw):
        findings.append(_finding(
            "server_blamed_for_client_error", "diagnostic_clarity", "medium",
            "A client error is being reported as a server error",
            "Snippet: %s" % _match_line(raw, r"\b(400|401|403|404|422)\b", 140),
            "The wrong status code sends the incident to the wrong team and pollutes the 5xx budget "
            "with traffic that is really the caller's fault.",
            "Map upstream 4xx responses to 4xx responses and only 5xx to 5xx.",
        ))

    # 26. no environment context
    if not ENV_RE.search(raw):
        findings.append(_finding(
            "no_env_context", "diagnostic_clarity", "low",
            "Nothing identifies the environment or build",
            "Paste length: %d characters" % len(raw),
            "The same trace means different things in staging and production, and half of the "
            "environment-specific causes (a missing migration, an old image) are invisible without it.",
            "Paste alongside the deploy version, the environment name and the instance id.",
        ))

    # 26b. several occurrences in one paste
    if ctx["occurrence_count"] > 1:
        findings.append(_finding(
            "multiple_occurrences_pasted", "diagnostic_clarity", "low",
            "The paste contains several occurrences",
            "Occurrences: %d" % ctx["occurrence_count"],
            "One paste with many failures forces you to triage all of them at once. The "
            "single-error analysis below covers the first one.",
            "Use the cluster view to see which signature dominates, then analyse that one on its own.",
        ))

    # 27. several unrelated error types in one paste
    types = {e.error_type for e in ctx["errors"] if e.error_type}
    if len(types) > 2:
        findings.append(_finding(
            "mixed_error_types", "diagnostic_clarity", "low",
            "Several different exception types are mixed together",
            "Types: %s" % ", ".join(sorted(types)[:5]),
            "One paste that contains three unrelated failures forces you to triage all three at "
            "once, and the interesting one gets lost.",
            "Split the paste so each occurrence is analysed on its own, then use the cluster view to "
            "see the pattern.",
        ))

    # 28. connection handles in a resource failure
    if cat_id == "resource_exhaustion" and re.search(r"connection", raw, re.I):
        findings.append(_finding(
            "connection_not_closed", "fix_safety", "high",
            "Connections are involved in a resource exhaustion failure",
            "Snippet: %s" % _match_line(raw, r"connection", 140),
            "When the pool is empty on the failure path, the handles are probably being leaked on "
            "the error path, not under normal load.",
            "Return the connection in a finally block or a context manager, and log the in-use count "
            "so the leak is visible before it becomes an outage.",
        ))

    # 29. log lines with no level
    if logs and not any(e.level for e in logs):
        findings.append(_finding(
            "log_level_missing", "observability", "low",
            "Log lines carry no severity level",
            "Sampled line: %s" % logs[0].raw[:140],
            "Without a level you cannot filter failures out of the noise, and alerting cannot pick "
            "them up either.",
            "Log through a structured logger that stamps a level on every line.",
        ))

    # 30. the same error repeated in the log
    if logs:
        counts = {}
        for e in logs:
            key = e.message.strip()[:120]
            counts[key] = counts.get(key, 0) + 1
        worst, worst_n = max(counts.items(), key=lambda kv: kv[1])
        if worst_n >= 3:
            findings.append(_finding(
                "repeated_error_lines", "observability", "low",
                "The same message repeats in the log",
                "Repeated %d times: %s" % (worst_n, worst[:110]),
                "Repetition is useful signal (it says how often and how fast) but it also means the "
                "log volume is dominated by one failure.",
                "Keep the repetition but rate-limit it, and add a counter metric for the failure "
                "instead of a line per occurrence.",
            ))

    return findings


# ---------------------------------------------------------------------------
# hypotheses
# ---------------------------------------------------------------------------


def _likelihood_label(weight: float) -> str:
    if weight >= 4.2:
        return "high"
    if weight >= 3.0:
        return "medium"
    return "low"


def _build_hypotheses(ctx: Dict[str, Any]) -> List[Dict[str, Any]]:
    cat = get_category(ctx["category"]["id"])
    out: List[Dict[str, Any]] = []

    frame = ctx["origin_frame"]
    if frame is not None and frame.in_app:
        out.append({
            "cause": "The defect is in your own code at %s" % frame.location,
            "why": "The first frame that belongs to application code is %s (%s)"
                   % (frame.location, frame.function or "unknown function"),
            "check": "Open %s and inspect the values the message names, then reproduce with the "
                     "exact input from the log." % (frame.project or frame.location),
            "weight": 5.0,
            "evidence": [frame.raw[:180]],
        })
    elif frame is not None:
        out.append({
            "cause": "The fault is in configuration or the environment, not in application logic",
            "why": "Every frame in the trace is in %s code" % frame.origin,
            "check": "Check the configuration, credentials and resolved dependency version that this "
                     "call site uses.",
            "weight": 4.0,
            "evidence": [frame.raw[:180]],
        })
    else:
        out.append({
            "cause": "The failure is not localised yet, so start from the trigger",
            "why": "No usable stack frame was parsed from the paste",
            "check": "Re-copy the paste from the first line of the error, then search the codebase "
                     "for the failing operation name.",
            "weight": 3.5,
            "evidence": [],
        })

    if cat:
        for h in cat["hypotheses"]:
            out.append({
                "cause": h["cause"],
                "why": h["why"],
                "check": h["check"],
                "weight": float(h["weight"]),
                "evidence": [],
            })

    text = ctx["raw"]
    if re.search(r"https?://|Connection refused|ECONNREFUSED|timed out|502|503", text, re.I):
        out.append({
            "cause": "The failure happened at a network boundary, so the payload or the peer changed",
            "why": "The trace mentions an HTTP call or a socket error",
            "check": "Capture the exact request and response bytes for one failing call and compare "
                     "them with a working one.",
            "weight": 3.5,
            "evidence": [_match_line(text, r"https?://|Connection refused|ECONNREFUSED|502|503", 160)],
        })

    if re.search(r"\b(retr(?:y|ies|ying))\b", text, re.I):
        out.append({
            "cause": "The operation is not idempotent, so a retry left partial state behind",
            "why": "Retries appear in the same paste as the failure",
            "check": "Check whether the failing operation was already applied once before the retry, "
                     "and whether it is safe to run twice.",
            "weight": 3.0,
            "evidence": [_match_line(text, r"\b(retr(?:y|ies|ying))\b", 160)],
        })

    if ctx["category"]["id"] == "unknown":
        out.append({
            "cause": "The paste is incomplete - the header line is missing",
            "why": "No known signature matched the text",
            "check": "Re-copy the paste starting at the line that names the exception, including any "
                     "'Caused by' section.",
            "weight": 4.0,
            "evidence": [],
        })

    seen = set()
    unique = []
    for h in out:
        key = h["cause"].lower()[:80]
        if key in seen:
            continue
        seen.add(key)
        unique.append(h)

    unique.sort(key=lambda h: -h["weight"])
    ranked = []
    for i, h in enumerate(unique):
        ranked.append({
            "rank": i + 1,
            "cause": h["cause"],
            "why": h["why"],
            "check": h["check"],
            "likelihood": _likelihood_label(h["weight"]),
            "weight": round(h["weight"], 1),
            "evidence": h["evidence"],
        })
    return ranked


# ---------------------------------------------------------------------------
# message quality
# ---------------------------------------------------------------------------


def _message_quality(ctx: Dict[str, Any]) -> Dict[str, Any]:
    primary = ctx["primary"]
    msg = primary.message if primary else ""
    etype = (primary.error_type if primary else "") or ""
    score = 0
    issues = []

    if etype and etype.strip().lower() not in GENERIC_TYPES:
        score += 25
    else:
        issues.append("the exception type is missing or generic")

    if len(msg) >= 15:
        score += 18
    else:
        issues.append("the message is shorter than 15 characters")

    if ID_RE.search(msg):
        score += 20
    else:
        issues.append("the message names no identifier or value")

    if len(msg.split()) >= 4:
        score += 15
    else:
        issues.append("the message is too terse to be searchable")

    if msg and not VAGUE_RE.search(msg):
        score += 22
    else:
        issues.append("the wording is vague")

    if primary is not None and primary.frames:
        score += 10
    else:
        issues.append("the failure is not tied to a location")

    score = max(0, min(100, score))
    suggested = _suggest_message(ctx)
    return {"score": score, "issues": issues, "suggested_message": suggested}


def _suggest_message(ctx: Dict[str, Any]) -> str:
    primary = ctx["primary"]
    etype = (primary.error_type if primary else "") or "Error"
    msg = (primary.message if primary else "").strip()
    frame = ctx["origin_frame"]
    loc = frame.location if frame else "unknown location"
    reasons = {
        "null_reference": "the record was missing when it was dereferenced",
        "type_error": "the input did not have the expected type or shape",
        "index_bounds": "the collection was shorter than the code assumed",
        "dependency_mismatch": "the dependency was not present on the classpath",
        "config_missing": "a required configuration value was absent",
        "timeout": "the operation exceeded its deadline",
        "connectivity": "the upstream service could not be reached",
        "auth": "the credential was rejected",
        "database": "the database rejected the query",
        "bad_data": "the payload could not be parsed",
    }
    reason = reasons.get(ctx["category"]["id"], "the operation failed")
    return ("Failed to <operation> for <entity>: %s (%s: %s at %s)"
            % (reason, etype, msg[:120] or "no detail", loc))


# ---------------------------------------------------------------------------
# triage checklist and reproduction
# ---------------------------------------------------------------------------

_CATEGORY_TRIAGE = {
    "null_reference": "Log the object and its fields immediately before the deref, then re-run with the "
                      "exact input from the log.",
    "type_error": "Capture one raw payload that fails and diff it against one that succeeds.",
    "index_bounds": "Log the collection length next to the index; check the empty and size-one cases.",
    "dependency_mismatch": "Compare the manifest, the lockfile and the built artifact, not just the "
                           "source tree.",
    "resource_exhaustion": "Take a heap histogram or a thread dump during the failure, and check "
                           "whether handles are returned on the error path.",
    "timeout": "Compare the configured timeout with the observed p95 duration of that call.",
    "connectivity": "Call the dependency directly from the same network and check the deploy timeline.",
    "auth": "Decode the token or credential and compare expiry, issuer and scope.",
    "config_missing": "Print the config keys of the running process and diff against the code.",
    "concurrency": "Get a thread dump or lock ordering for the two paths that collide.",
    "database": "Compare the applied migrations in the failing database with the repository head.",
    "bad_data": "Capture the raw body and locate the exact position that failed to parse.",
}


def _build_triage(ctx: Dict[str, Any]) -> List[Dict[str, Any]]:
    frame = ctx["origin_frame"]
    loc = frame.location if frame else "the failing call"
    steps = [
        {
            "step": 1,
            "timebox": "2 min",
            "action": "Read the root cause line, not the top of the trace",
            "detail": "The first line is where the failure surfaced; the deepest 'Caused by' entry is "
                      "usually where the fault actually is. The frames in between are the call path.",
        },
        {
            "step": 2,
            "timebox": "3 min",
            "action": "Open the origin frame at %s" % loc,
            "detail": "The origin frame is the first frame in your own code. If there is none, the "
                      "fault is in configuration, credentials or a dependency.",
        },
    ]
    cat_step = _CATEGORY_TRIAGE.get(ctx["category"]["id"])
    if cat_step:
        steps.append({
            "step": len(steps) + 1,
            "timebox": "10 min",
            "action": "Run the discriminating check for this failure class",
            "detail": cat_step,
        })
    steps.extend([
        {
            "step": len(steps) + 1,
            "timebox": "10 min",
            "action": "Reproduce with the exact input from the paste",
            "detail": "Same id, same payload, same environment. If it does not reproduce, it is "
                      "timing, ordering or data dependent - move to the concurrency check.",
        },
        {
            "step": len(steps) + 1,
            "timebox": "5 min",
            "action": "Check what changed in the failure window",
            "detail": "Deploy, config change, dependency bump, schema migration, traffic shape. The "
                      "cause is usually in the diff between working and broken.",
        },
        {
            "step": len(steps) + 1,
            "timebox": "10 min",
            "action": "Test the top hypothesis, then the second",
            "detail": "Work the ranked hypotheses in order. Each one has a specific check; a check "
                      "that returns nothing eliminates a cause in minutes.",
        },
        {
            "step": len(steps) + 1,
            "timebox": "10 min",
            "action": "Close the observability gap while you are here",
            "detail": "Add the correlation id, the identifier and the stack trace that were missing, "
                      "so the next occurrence is a two-minute job instead of an hour.",
        },
        {
            "step": len(steps) + 1,
            "timebox": "15 min",
            "action": "Fix at the narrowest point and add the regression test",
            "detail": "Fix the producer of the bad value if you can. If the fix changes data, money "
                      "or concurrency, review it with a second pair of eyes.",
        },
    ])
    for s in steps:
        s["step"] = steps.index(s) + 1
    return steps


_REPRO = {
    "python": (
        "def test_repro():\n"
        "    # input from the paste\n"
        "    payload = <the exact input>\n"
        "    with pytest.raises(<ErrorType>):\n"
        "        <the call at {loc}>\n"
    ),
    "java": (
        "public class ReproTest {\n"
        "    @Test\n"
        "    void reproduces() {\n"
        "        // input from the paste\n"
        "        var payload = <the exact input>;\n"
        "        assertThrows(<ErrorType>.class, () -> <the call at {loc}>);\n"
        "    }\n"
        "}\n"
    ),
    "javascript": (
        "test('reproduces', async () => {\n"
        "  const payload = <the exact input>;\n"
        "  await expect(<the call at {loc}>).rejects.toThrow(/<message fragment>/);\n"
        "});\n"
    ),
    "csharp": (
        "[Fact]\n"
        "public void Reproduces()\n"
        "{\n"
        "    var payload = <the exact input>;\n"
        "    Assert.Throws<<ErrorType>>(() => <the call at {loc}>);\n"
        "}\n"
    ),
    "go": (
        "func TestRepro(t *testing.T) {\n"
        "\tpayload := <the exact input>\n"
        "\tdefer func() {\n"
        "\t\tif r := recover(); r == nil {\n"
        "\t\t\tt.Fatalf(\"expected a panic at {loc}\")\n"
        "\t\t}\n"
        "\t}()\n"
        "\t<the call at {loc}>\n"
        "}\n"
    ),
    "rust": (
        "#[test]\n"
        "fn reproduces() {\n"
        "    let payload = <the exact input>;\n"
        "    let result = std::panic::catch_unwind(|| <the call at {loc}>);\n"
        "    assert!(result.is_err());\n"
        "}\n"
    ),
    "ruby": (
        "test \"reproduces\" do\n"
        "  payload = <the exact input>\n"
        "  assert_raises(<ErrorType>) { <the call at {loc}> }\n"
        "end\n"
    ),
    "php": (
        "public function testReproduces(): void\n"
        "{\n"
        "    $payload = <the exact input>;\n"
        "    $this->expectException(\\Exception::class);\n"
        "    // <the call at {loc}>\n"
        "}\n"
    ),
}


def _build_repro(ctx: Dict[str, Any]) -> Dict[str, Any]:
    lang = ctx["language"]
    primary = ctx["primary"]
    frame = ctx["origin_frame"]
    loc = frame.location if frame else "the failing call"
    etype = (primary.error_type if primary else "") or "the same exception"
    tmpl = _REPRO.get(lang)
    if tmpl is None:
        tmpl = (
            "# Reproduce the failure with the exact input from the paste.\n"
            "# 1. Paste the payload that failed.\n"
            "# 2. Call the failing operation: <the call at {loc}>\n"
            "# 3. Assert it raises: <ErrorType>\n"
        )
    skeleton = tmpl.replace("{loc}", loc).replace("{ErrorType}", etype)
    return {
        "language": lang,
        "skeleton": skeleton,
        "location": loc,
    }


# ---------------------------------------------------------------------------
# log signals
# ---------------------------------------------------------------------------


def _log_signals(ctx: Dict[str, Any]) -> Dict[str, Any]:
    logs = ctx["logs"]
    levels: Dict[str, int] = {}
    for e in logs:
        if e.level:
            levels[e.level] = levels.get(e.level, 0) + 1
    stamps = [e.timestamp for e in logs if e.timestamp]
    messages: Dict[str, int] = {}
    for e in logs:
        key = e.message.strip()[:120]
        messages[key] = messages.get(key, 0) + 1
    repeated = sorted([(m, n) for m, n in messages.items() if n >= 2], key=lambda kv: -kv[1])[:5]
    return {
        "has_logs": bool(logs),
        "line_count": len(logs),
        "levels": levels,
        "error_lines": sum(1 for e in logs if e.level in ("ERROR", "FATAL", "CRITICAL")),
        "warn_lines": sum(1 for e in logs if e.level in ("WARN", "WARNING")),
        "has_timestamps": bool(stamps),
        "first_timestamp": stamps[0] if stamps else None,
        "last_timestamp": stamps[-1] if stamps else None,
        "has_correlation_id": any(CORRELATION_RE.search(e.raw) for e in logs),
        "distinct_messages": len(messages),
        "repeated_messages": [{"message": m, "count": n} for m, n in repeated],
        "loggers": sorted({e.logger for e in logs if e.logger}),
    }


# ---------------------------------------------------------------------------
# fix plan
# ---------------------------------------------------------------------------


def _build_fix_plan(ctx: Dict[str, Any], findings: List[Dict[str, Any]],
                    hypotheses: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    plan: List[Dict[str, Any]] = []
    if hypotheses:
        top = hypotheses[0]
        plan.append({
            "title": "Confirm the top hypothesis: %s" % top["cause"],
            "detail": top["check"],
            "axis": "fix_confidence",
            "kind": "investigate",
            "gain": 0,
            "effort": "15 min",
        })
    order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    for f in sorted(findings, key=lambda x: (order.get(x["severity"], 2), x["id"])):
        plan.append({
            "title": f["title"],
            "detail": f["fix"],
            "axis": f["axis"],
            "kind": "fix",
            "gain": round({"critical": 13.0, "high": 7.5, "medium": 4.0, "low": 1.5}[f["severity"]], 1),
            "effort": {"critical": "1 h", "high": "30 min", "medium": "15 min", "low": "5 min"}[f["severity"]],
            "severity": f["severity"],
        })
    plan.sort(key=lambda p: (0 if p["kind"] == "investigate" else 1, -p["gain"], p["title"]))
    for i, p in enumerate(plan):
        p["rank"] = i + 1
    return plan


# ---------------------------------------------------------------------------
# structural caps
# ---------------------------------------------------------------------------


def _structural_caps(ctx: Dict[str, Any], findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    ids = {f["id"] for f in findings}
    caps: List[Dict[str, Any]] = []
    cat = ctx["category"]

    if "no_frames" in ids:
        caps.append({"axis": "root_cause_localisation", "cap": 35, "overall_cap": 50,
                     "reason": "no stack frames: the failure cannot be localised from this paste"})
    if "vague_message" in ids and "no_error_type" in ids:
        caps.append({"axis": "diagnostic_clarity", "cap": 28, "overall_cap": 52,
                     "reason": "no exception type and a vague message"})
    elif "vague_message" in ids:
        caps.append({"axis": "diagnostic_clarity", "cap": 34, "overall_cap": 58,
                     "reason": "the message says nothing specific"})
    if cat["id"] == "unknown":
        caps.append({"axis": "fix_confidence", "cap": 45, "overall_cap": 62,
                     "reason": "the failure does not match any known error class"})
    if "secret_in_log" in ids:
        caps.append({"axis": "observability", "cap": 32, "overall_cap": 66,
                     "reason": "a credential is exposed in the pasted output"})
    elif "error_without_trace" in ids:
        caps.append({"axis": "observability", "cap": 40, "overall_cap": 58,
                     "reason": "the error was logged without a stack trace"})
    if "trace_leaked_to_client" in ids:
        caps.append({"axis": "observability", "cap": 40, "overall_cap": 60,
                     "reason": "the trace is exposed to callers"})
    if cat["severity"] == "critical":
        caps.append({"axis": "fix_safety", "cap": 45, "overall_cap": 72,
                     "reason": "this class of failure carries real damage risk"})
    if "library_only_frames" in ids:
        caps.append({"axis": "root_cause_localisation", "cap": 52,
                     "reason": "no application frame in the trace"})
    return caps


# ---------------------------------------------------------------------------
# entry point
# ---------------------------------------------------------------------------


def analyze(text: str, profile: str = "general", language: str = "auto") -> Dict[str, Any]:
    """Analyse a pasted stack trace or log excerpt."""
    if profile not in PROFILES:
        profile = "general"

    parsed = parsers.parse_input(text, language)
    errors: List[parsers.ParsedError] = parsed["errors"]
    logs = parsed["logs"]
    occurrences = parsed.get("occurrences", [])

    if not errors and not logs:
        return {
            "meta": {"language": "unknown", "occurrence_count": 0, "error_count": 0, "log_count": 0,
                     "has_logs": False},
            "primary": None,
            "chain": [],
            "classification": {"id": "unknown", "label": "No failure detected", "severity": "medium",
                               "summary": "Nothing that looks like a failure was found in the paste.",
                               "confidence": 0, "match_count": 0},
            "hypotheses": [],
            "findings": [{
                "id": "no_failure_detected", "axis": "diagnostic_clarity", "severity": "high",
                "title": "No failure detected in the paste",
                "evidence": "Paste length: %d characters" % len(text or ""),
                "why_it_matters": "There is nothing to triage. Either the paste is the wrong thing, "
                                  "or it is missing the error itself.",
                "fix": "Paste the exception header plus the full stack trace, or the log lines that "
                       "contain the failure.",
            }],
            "red_flags": [],
            "triage": [],
            "repro": {"language": "unknown", "skeleton": "", "location": ""},
            "message_quality": {"score": 0, "issues": ["nothing was pasted"], "suggested_message": ""},
            "scorecard": {
                "axes": [], "overall": 0.0, "profile": profile,
                "profile_label": PROFILES[profile]["label"], "weights": PROFILES[profile]["weights"],
                "caps": [], "verdict": "not_diagnosable",
                "verdict_blurb": "There is not enough here to act on. Start with the triage checklist.",
            },
            "fix_plan": [],
            "logs": _log_signals({"logs": []}),
        }

    chain = occurrences[0]["errors"] if occurrences else list(errors)
    primary = chain[-1] if chain else None
    if primary is not None and primary.chain_marker == "Suppressed" and len(chain) > 1:
        primary = chain[-2]
    if primary is None and logs:
        seed = None
        for entry in logs:
            if entry.level in ("ERROR", "FATAL", "CRITICAL"):
                seed = entry
                break
        if seed is None:
            seed = logs[0]
        primary = parsers.ParsedError(language=parsed["language"], error_type="",
                                      message=seed.message, raw=seed.raw,
                                      level=seed.level, timestamp=seed.timestamp)

    class_text = "\n".join([e.headline for e in chain]) or text
    classification = match_category(class_text)
    frame = _origin_frame(primary) if primary else None

    ctx = {
        "raw": text or "",
        "errors": errors,
        "logs": logs,
        "chain": chain,
        "primary": primary,
        "origin_frame": frame,
        "category": classification,
        "language": parsed["language"],
        "occurrence_count": parsed["occurrence_count"],
    }

    findings = _rules(ctx)
    hypotheses = _build_hypotheses(ctx)

    in_app = [f for f in (primary.frames if primary else []) if f.in_app]
    library_frames = [f for f in (primary.frames if primary else []) if f.origin in ("library", "framework", "stdlib")]

    localisation = 20.0
    if frame is not None:
        localisation = 55.0
        if frame.in_app:
            localisation = 88.0
        if frame.line:
            localisation += 8.0
        if len(in_app) > 1:
            localisation += 2.0
    elif primary is not None and primary.frames:
        localisation = 40.0
    if len(chain) > 1:
        localisation += 4.0

    clarity = 30.0
    if primary is not None and primary.error_type:
        clarity += 25.0
    if primary is not None and len(primary.message) > 15:
        clarity += 20.0
    if primary is not None and ID_RE.search(primary.message):
        clarity += 15.0
    if primary is not None and not VAGUE_RE.search(primary.message or "x"):
        clarity += 10.0

    confidence = 45.0
    if classification["id"] != "unknown":
        confidence += 22.0
    if classification["match_count"] >= 2:
        confidence += 6.0
    if frame is not None and frame.in_app:
        confidence += 12.0
    if hypotheses:
        confidence += min(10.0, len(hypotheses) * 1.5)

    observability = 25.0
    if logs:
        observability += 18.0
        if any(e.timestamp for e in logs):
            observability += 14.0
        if any(CORRELATION_RE.search(e.raw) for e in logs):
            observability += 18.0
        if any(e.level for e in logs):
            observability += 10.0
        if primary is not None and primary.frames:
            observability += 15.0
    else:
        observability += 20.0 if (primary is not None and primary.frames) else 8.0

    cat_meta = get_category(classification["id"]) or {}
    safety = float(cat_meta.get("fix_risk", 60))
    if primary is not None and primary.frames and frame is not None and frame.in_app:
        safety += 8.0
    if frame is None:
        safety -= 10.0

    axis_scores = {
        "diagnostic_clarity": clarity,
        "root_cause_localisation": localisation,
        "fix_confidence": confidence,
        "observability": observability,
        "fix_safety": safety,
    }

    caps = _structural_caps(ctx, findings)
    scorecard = score_review(axis_scores, findings, profile, caps)

    red_flags = [f for f in findings if f["severity"] in ("critical", "high")]

    primary_out = None
    if primary is not None:
        pd = primary.to_dict()
        pd["origin_frame"] = frame.to_dict() if frame else None
        pd["in_app_frame_count"] = len(in_app)
        pd["library_frame_count"] = len(library_frames)
        pd["chain_length"] = len(chain)
        primary_out = pd

    return {
        "meta": {
            "language": parsed["language"],
            "occurrence_count": parsed["occurrence_count"],
            "error_count": len(errors),
            "log_count": len(logs),
            "has_logs": bool(logs),
            "paste_length": len(text or ""),
        },
        "primary": primary_out,
        "chain": [e.to_dict() for e in chain],
        "classification": classification,
        "hypotheses": hypotheses,
        "findings": findings,
        "red_flags": red_flags,
        "triage": _build_triage(ctx),
        "repro": _build_repro(ctx),
        "message_quality": _message_quality(ctx),
        "scorecard": scorecard,
        "fix_plan": _build_fix_plan(ctx, findings, hypotheses),
        "logs": _log_signals(ctx),
    }
