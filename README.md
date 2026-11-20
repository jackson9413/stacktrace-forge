# stacktrace-forge

**Local-first stack trace and log triage workbench.**

Paste a stack trace or a log excerpt. Get back the origin frame, the cause chain,
ranked hypotheses with the check that discriminates between them, a time-boxed
triage checklist, a minimal reproduction skeleton, and a five-axis 0-100 scorecard
with a prioritised fix plan.

No API keys. No network calls. No LLM. Nothing leaves the machine.

---

## Why it exists

Every developer has lost an hour to a stack trace that says

~~~
java.lang.NullPointerException
~~~

and nothing else. Or to a log excerpt with five different failures in it and no
idea which one matters. Or to a paste that turns out to contain a live API key.

stacktrace-forge answers three questions about any failure:

1. **Where is it?** The first frame in your own code, not the framework frame above it.
2. **Why?** A ranked list of hypotheses, each with the concrete check that tells them apart.
3. **What do I do first?** A time-boxed checklist ordered by how fast it eliminates a cause.

It also tells you when the paste is bad: a vague message, a swallowed exception, a
trace logged at INFO, a missing correlation id, a credential in the output.

## What it does

- **Parses 8 languages**: Java, Python, JavaScript/Node, C#, Go, Rust, Ruby, PHP.
  Each trace is split into its cause chain, and each frame is classified as
  application code, test code, library, framework or stdlib.
- **Classifies the failure** against a local taxonomy of 18 failure classes
  (null dereference, type mismatch, index bounds, dependency resolution, resource
  exhaustion, timeout, connectivity, auth, config, concurrency, database, bad data,
  assertion, rate limit, permission, numeric, unclassified), each with its own
  severity and fix-risk profile.
- **Ranks hypotheses.** Every failure class carries prior hypotheses; the analyser
  adds evidence-driven ones (the origin frame, a network boundary, a retry, a
  missing header) and ranks them by likelihood.
- **Finds the problems that waste debugging time**: vague messages, generic
  exception types, swallowed exceptions, bare excepts, generic wrappers, deep cause
  chains, errors logged without a trace, traces logged below ERROR, missing
  correlation ids, credentials and PII in logs, missing timestamps, unhandled
  promise rejections, retries without backoff, unvalidated input, traces leaked to
  callers, repeating frames, missing null guards, client errors reported as 5xx,
  missing environment context, and more.
- **Scores the paste** on five axes: diagnostic clarity, root-cause localisation,
  fix confidence, observability and fix safety. Structural caps stop a thin paste
  from scoring well by skipping the hard part.
- **Clusters repeated occurrences** by normalised signature, so a night of failures
  becomes one dominant cause and a named tail.
- **Exports** a Markdown report, a JSON blob or a CSV of the findings.

## Quick start

~~~
pip install -r requirements.txt
python3 app.py
~~~

Then open http://127.0.0.1:8765

Or:

~~~
./run.sh
~~~

The run script honours the PORT environment variable (default 8765).

## Tests

~~~
python3 -m unittest discover -s tests -v
~~~

The suite covers the parsers for all eight languages, the taxonomy, the scoring
caps, the clustering, the exports, every REST endpoint, and a frontend/backend
contract check that asserts the UI reads only fields the API actually returns.

## The six built-in samples

| Sample | What it shows |
| --- | --- |
| java_npe_chain | The control case. A NullPointerException whose real cause is one Caused by level down. Scores 93 (diagnosable) and localises to ContractRepository.java:64. |
| java_generic_wrapper | A bare RuntimeException and the message "import failed". Scores 58 (mostly actionable). |
| node_secret_undefined | A precise TypeError - with a live API key in the log line above it. Scores 66 and raises a critical red flag. |
| go_panic_recursion | A Go panic with the same frame repeated nine times. Scores 79 and flags the repeating frame as the loop that never ends. |
| log_vague_no_trace | Four error lines: no timestamps, no trace, a customer email, a bare retry. Scores 31 (not diagnosable). |
| repeated_occurrences | Five occurrences of one night, separated by lines of three dashes. Scores 85, and clusters into three signatures with one dominant. |

Load them from the sample dropdown in the UI, or read them in samples/.

## Profiles

The five axes are re-weighted per profile, because "good" depends on why you are
looking at a failure:

| Profile | Weights |
| --- | --- |
| general | Balanced. |
| incident | Localisation and observability up: you are on a page right now. |
| postmortem | Clarity and observability up: what must change so it never repeats. |
| code_review | Clarity and fix safety up: you are reviewing the error handling itself. |
| repro | Localisation and confidence up: you are turning it into a failing test. |
| dependency | Localisation and confidence up, observability down: classpath and version problems. |

## REST API

| Method | Path | Purpose |
| --- | --- | --- |
| GET | /api/health | Liveness check. |
| GET | /api/profiles | The profiles and their axis weights. |
| GET | /api/samples | Sample metadata (no text). |
| GET | /api/samples/<id> | One sample with its full text. |
| POST | /api/analyze | Analyse a paste. Body: text, profile, language. |
| POST | /api/cluster | Cluster occurrences. Body: text or texts[]. |
| POST | /api/export | Export a report. Body: text, profile, format (markdown/json/csv). |
| GET/POST | /api/runs | List or save a run. |
| GET/PATCH/DELETE | /api/runs/<id> | Read, update (rating, notes) or delete a run. |

Example:

~~~
curl -s localhost:8765/api/analyze \
  -H 'Content-Type: application/json' \
  -d '{"text":"java.lang.NullPointerException: boom"}'
~~~

## Layout

~~~
app.py              Flask app: REST API, static UI, SQLite run log
engine/
  parsers.py        Trace and log parsing for 8 languages, frame classification
  taxonomy.py       18 failure classes with hypotheses, severity and fix risk
  analysis.py       Rules, hypotheses, triage checklist, repro, scorecard wiring
  scoring.py        Five axes, weights per profile, structural caps, verdict bands
  cluster.py        Signature normalisation and occurrence clustering
  export.py         Markdown, JSON and CSV exports
static/             Dark vanilla-JS UI (no build step, no framework)
samples/            Six calibration samples and their index
tests/              Engine tests, API tests, frontend contract check
~~~

## Design notes

- **Standard library only** apart from Flask. Every calculation - the taxonomy
  match, the hypothesis ranking, the caps, the clustering - happens locally.
- **The root cause wins.** For a cause chain, the deepest entry is the primary
  failure; the frames above it are the call path. The UI shows both.
- **Findings carry evidence.** Every finding names the exact snippet that
  triggered it, why it matters, and the concrete fix.
- **Caps are structural.** A paste with no stack frames cannot score well on
  localisation no matter how nice the message is, and the scorecard says which
  cap was applied and why.

## Domain rotation slot

**Developer tools / debugging and error triage.** The next build should pick a
different slot - real estate, recruiting, travel, health, learning, or a niche
B2B workflow are all under-covered.
