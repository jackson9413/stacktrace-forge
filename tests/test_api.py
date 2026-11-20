"""API tests for stacktrace-forge."""

import json
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

os.environ["STACKTRACE_FORGE_DB"] = os.path.join(tempfile.mkdtemp(), "test.sqlite3")

import app as forge  # noqa: E402

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SAMPLES_DIR = os.path.join(BASE, "samples")

with open(os.path.join(SAMPLES_DIR, "index.json"), "r", encoding="utf-8") as fh:
    SAMPLE_INDEX = json.load(fh)


def sample_text(sample_id):
    for s in SAMPLE_INDEX:
        if s["id"] == sample_id:
            with open(os.path.join(SAMPLES_DIR, s["file"]), "r", encoding="utf-8") as fh:
                return fh.read()
    raise AssertionError("missing sample " + sample_id)


class ApiTests(unittest.TestCase):
    def setUp(self):
        forge.app.config["TESTING"] = True
        self.client = forge.app.test_client()

    def test_health(self):
        res = self.client.get("/api/health")
        self.assertEqual(res.status_code, 200)
        self.assertTrue(res.get_json()["ok"])

    def test_index_page_served(self):
        res = self.client.get("/")
        self.assertEqual(res.status_code, 200)
        self.assertIn(b"stacktrace-forge", res.data)

    def test_profiles(self):
        res = self.client.get("/api/profiles")
        data = res.get_json()
        self.assertGreaterEqual(len(data["profiles"]), 4)
        ids = [p["id"] for p in data["profiles"]]
        self.assertIn("incident", ids)
        self.assertIn("postmortem", ids)

    def test_samples_list_and_detail(self):
        res = self.client.get("/api/samples")
        data = res.get_json()
        self.assertEqual(len(data["samples"]), len(SAMPLE_INDEX))
        for s in data["samples"]:
            self.assertNotIn("text", s)
        res = self.client.get("/api/samples/java_npe_chain")
        data = res.get_json()
        self.assertIn("NullPointerException", data["text"])

    def test_analyze_endpoint(self):
        res = self.client.post("/api/analyze", json={
            "text": sample_text("java_npe_chain"), "profile": "general"})
        data = res.get_json()
        self.assertEqual(data["meta"]["language"], "java")
        self.assertGreater(data["scorecard"]["overall"], 80)
        self.assertTrue(data["hypotheses"])

    def test_analyze_rejects_bad_input(self):
        res = self.client.post("/api/analyze", json={"text": 42})
        self.assertEqual(res.status_code, 400)

    def test_analyze_empty(self):
        res = self.client.post("/api/analyze", json={"text": ""})
        data = res.get_json()
        self.assertEqual(data["scorecard"]["overall"], 0)

    def test_cluster_endpoint(self):
        res = self.client.post("/api/cluster", json={"text": sample_text("repeated_occurrences")})
        data = res.get_json()
        self.assertEqual(data["total_occurrences"], 5)
        self.assertEqual(data["distinct_signatures"], 3)

    def test_export_endpoint_formats(self):
        for fmt, marker in (("markdown", b"# stacktrace-forge"), ("json", b"scorecard"),
                            ("csv", b"kind,rank")):
            res = self.client.post("/api/export", json={
                "text": sample_text("java_npe_chain"), "format": fmt})
            self.assertEqual(res.status_code, 200)
            self.assertIn(marker, res.data)

    def test_run_lifecycle(self):
        analysis_result = self.client.post("/api/analyze", json={
            "text": sample_text("java_npe_chain")}).get_json()
        res = self.client.post("/api/runs", json={
            "result": analysis_result, "paste": "trace", "self_rating": 4, "notes": "good"})
        self.assertEqual(res.status_code, 201)
        run_id = res.get_json()["id"]

        res = self.client.get("/api/runs")
        self.assertGreaterEqual(len(res.get_json()["runs"]), 1)

        res = self.client.get("/api/runs/%d" % run_id)
        self.assertEqual(res.status_code, 200)
        self.assertEqual(res.get_json()["self_rating"], 4)

        res = self.client.patch("/api/runs/%d" % run_id, json={"notes": "updated"})
        self.assertEqual(res.status_code, 200)
        self.assertEqual(self.client.get("/api/runs/%d" % run_id).get_json()["notes"], "updated")

        res = self.client.delete("/api/runs/%d" % run_id)
        self.assertEqual(res.status_code, 200)
        self.assertEqual(self.client.get("/api/runs/%d" % run_id).status_code, 404)


if __name__ == "__main__":
    unittest.main()
