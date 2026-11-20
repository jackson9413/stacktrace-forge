"""stacktrace-forge - local-first stack trace and log triage workbench.

Flask app: REST API, static UI and a SQLite log of saved analyses.
No API keys, no network calls, no LLM.
"""

import json
import os
import sqlite3
from datetime import datetime, timezone

from flask import Flask, Response, jsonify, request, send_from_directory

from engine import analysis, cluster, export

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
SAMPLES_DIR = os.path.join(BASE_DIR, "samples")
STATIC_DIR = os.path.join(BASE_DIR, "static")
DB_PATH = os.environ.get("STACKTRACE_FORGE_DB", os.path.join(BASE_DIR, "stacktrace_forge.sqlite3"))

app = Flask(__name__, static_folder=STATIC_DIR, static_url_path="/static")


# ---------------------------------------------------------------------------
# storage
# ---------------------------------------------------------------------------


def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    with get_db() as conn:
        conn.execute(
            """CREATE TABLE IF NOT EXISTS runs (
                   id INTEGER PRIMARY KEY AUTOINCREMENT,
                   created_at TEXT NOT NULL,
                   profile TEXT,
                   language TEXT,
                   category TEXT,
                   score REAL,
                   verdict TEXT,
                   occurrence_count INTEGER,
                   self_rating INTEGER,
                   notes TEXT,
                   paste TEXT,
                   result_json TEXT
               )"""
        )


@app.before_request
def _ensure_db():
    if request.path.startswith("/api/"):
        init_db()


# ---------------------------------------------------------------------------
# pages
# ---------------------------------------------------------------------------


@app.route("/")
def index():
    return send_from_directory(STATIC_DIR, "index.html")


# ---------------------------------------------------------------------------
# api
# ---------------------------------------------------------------------------


@app.route("/api/health")
def health():
    return jsonify({"ok": True, "service": "stacktrace-forge"})


@app.route("/api/profiles")
def profiles():
    out = []
    for pid, p in analysis.PROFILES.items():
        out.append({"id": pid, "label": p["label"], "description": p["description"],
                    "weights": p["weights"]})
    return jsonify({"profiles": out})


def _sample_index():
    path = os.path.join(SAMPLES_DIR, "index.json")
    if not os.path.exists(path):
        return []
    with open(path, "r", encoding="utf-8") as fh:
        return json.load(fh)


@app.route("/api/samples")
def samples():
    items = []
    for s in _sample_index():
        items.append({k: v for k, v in s.items() if k != "text"})
    return jsonify({"samples": items})


@app.route("/api/samples/<sample_id>")
def sample(sample_id):
    for s in _sample_index():
        if s["id"] == sample_id:
            path = os.path.join(SAMPLES_DIR, s.get("file") or (s["id"] + ".txt"))
            text = ""
            if os.path.exists(path):
                with open(path, "r", encoding="utf-8") as fh:
                    text = fh.read()
            out = {k: v for k, v in s.items() if k != "text"}
            out["text"] = text
            return jsonify(out)
    return jsonify({"error": "sample not found"}), 404


@app.route("/api/analyze", methods=["POST"])
def analyze():
    data = request.get_json(silent=True) or {}
    text = data.get("text") or ""
    profile = data.get("profile") or "general"
    language = data.get("language") or "auto"
    if not isinstance(text, str):
        return jsonify({"error": "text must be a string"}), 400
    result = analysis.analyze(text, profile=profile, language=language)
    return jsonify(result)


@app.route("/api/cluster", methods=["POST"])
def cluster_route():
    data = request.get_json(silent=True) or {}
    if "texts" in data and isinstance(data["texts"], list):
        text = "\n\n---\n\n".join(t for t in data["texts"] if isinstance(t, str))
    else:
        text = data.get("text") or ""
    language = data.get("language") or "auto"
    if not isinstance(text, str):
        return jsonify({"error": "text must be a string"}), 400
    result = cluster.cluster_occurrences(text, language=language)
    return jsonify(result)


@app.route("/api/export", methods=["POST"])
def export_route():
    data = request.get_json(silent=True) or {}
    text = data.get("text") or ""
    profile = data.get("profile") or "general"
    fmt = (data.get("format") or "markdown").lower()
    result = analysis.analyze(text, profile=profile)
    if fmt == "json":
        body = export.to_json(result)
        mimetype = "application/json"
        filename = "stacktrace-analysis.json"
    elif fmt == "csv":
        body = export.to_csv(result)
        mimetype = "text/csv"
        filename = "stacktrace-findings.csv"
    else:
        body = export.to_markdown(result)
        mimetype = "text/markdown"
        filename = "stacktrace-report.md"
    return Response(body, mimetype=mimetype, headers={
        "Content-Disposition": "attachment; filename=%s" % filename
    })


@app.route("/api/runs", methods=["POST"])
def create_run():
    data = request.get_json(silent=True) or {}
    result = data.get("result")
    if not isinstance(result, dict):
        return jsonify({"error": "result object required"}), 400
    sc = result.get("scorecard", {})
    meta = result.get("meta", {})
    cls = result.get("classification", {})
    with get_db() as conn:
        cur = conn.execute(
            """INSERT INTO runs (created_at, profile, language, category, score, verdict,
                                  occurrence_count, self_rating, notes, paste, result_json)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                datetime.now(timezone.utc).isoformat(timespec="seconds"),
                sc.get("profile", "general"),
                meta.get("language", "unknown"),
                cls.get("id", "unknown"),
                sc.get("overall", 0),
                sc.get("verdict", ""),
                meta.get("occurrence_count", 0),
                data.get("self_rating"),
                data.get("notes", ""),
                (data.get("paste") or "")[:20000],
                json.dumps(result, default=str)[:400000],
            ),
        )
        run_id = cur.lastrowid
    return jsonify({"id": run_id, "created": True}), 201


@app.route("/api/runs")
def list_runs():
    limit = int(request.args.get("limit", 50))
    with get_db() as conn:
        rows = conn.execute(
            "SELECT id, created_at, profile, language, category, score, verdict, "
            "occurrence_count, self_rating, notes FROM runs ORDER BY id DESC LIMIT ?",
            (limit,),
        ).fetchall()
    return jsonify({"runs": [dict(r) for r in rows]})


@app.route("/api/runs/<int:run_id>")
def get_run(run_id):
    with get_db() as conn:
        row = conn.execute("SELECT * FROM runs WHERE id = ?", (run_id,)).fetchone()
    if not row:
        return jsonify({"error": "run not found"}), 404
    data = dict(row)
    result = {}
    if data.get("result_json"):
        try:
            result = json.loads(data["result_json"])
        except ValueError:
            result = {}
    data["result"] = result
    return jsonify(data)


@app.route("/api/runs/<int:run_id>", methods=["PATCH"])
def update_run(run_id):
    data = request.get_json(silent=True) or {}
    fields = []
    values = []
    for key in ("self_rating", "notes"):
        if key in data:
            fields.append("%s = ?" % key)
            values.append(data[key])
    if not fields:
        return jsonify({"error": "nothing to update"}), 400
    values.append(run_id)
    with get_db() as conn:
        conn.execute("UPDATE runs SET %s WHERE id = ?" % ", ".join(fields), values)
    return jsonify({"id": run_id, "updated": True})


@app.route("/api/runs/<int:run_id>", methods=["DELETE"])
def delete_run(run_id):
    with get_db() as conn:
        conn.execute("DELETE FROM runs WHERE id = ?", (run_id,))
    return jsonify({"id": run_id, "deleted": True})


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 8765))
    print("stacktrace-forge running on http://127.0.0.1:%d" % port)
    app.run(host="127.0.0.1", port=port, debug=False)
