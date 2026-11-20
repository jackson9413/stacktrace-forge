"""Frontend/backend contract check for stacktrace-forge.

The UI is vanilla JS, so this test asserts that every endpoint it calls exists
in the Flask app and every response field it reads is actually returned.
"""

import os
import re
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

os.environ["STACKTRACE_FORGE_DB"] = os.path.join(
    os.path.dirname(os.path.abspath(__file__)), "contract.sqlite3")

import app as forge  # noqa: E402

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
STATIC_DIR = os.path.join(BASE, "static")


def read(name):
    with open(os.path.join(STATIC_DIR, name), "r", encoding="utf-8") as fh:
        return fh.read()


class ContractTests(unittest.TestCase):
    def setUp(self):
        forge.app.config["TESTING"] = True
        self.client = forge.app.test_client()
        self.js = read("app.js")
        self.html = read("index.html")

    GET_ENDPOINTS = ["/api/health", "/api/profiles", "/api/samples", "/api/runs"]
    POST_ENDPOINTS = ["/api/analyze", "/api/cluster", "/api/export"]

    def test_endpoints_used_by_the_ui_exist(self):
        called = set(re.findall(r"['\"](/api/[a-z/<>_\-]*)['\"]", self.js))
        self.assertTrue(called)
        known = set(self.GET_ENDPOINTS) | set(self.POST_ENDPOINTS) | {"/api/samples/",
                                                                    "/api/runs/"}
        self.assertEqual(called - known, set(),
                         "the UI calls an endpoint the app does not serve")
        for url in self.GET_ENDPOINTS:
            self.assertEqual(self.client.get(url).status_code, 200, url)
        for url in self.POST_ENDPOINTS:
            body = {"text": "ERROR - boom", "format": "markdown"}
            res = self.client.post(url, json=body)
            self.assertEqual(res.status_code, 200, url)
        res = self.client.get("/api/samples/java_npe_chain")
        self.assertEqual(res.status_code, 200)

    def test_response_fields_used_by_the_ui_are_returned(self):
        res = self.client.post("/api/analyze", json={
            "text": "java.lang.NullPointerException: boom\n\tat com.acme.A.b(A.java:1)\n"})
        data = res.get_json()
        required = ["meta", "primary", "classification", "hypotheses", "findings",
                    "triage", "repro", "message_quality", "scorecard", "fix_plan", "logs"]
        for key in required:
            self.assertIn(key, data)
            self.assertIn(key, self.js, "the UI never reads " + key)

    def test_scorecard_fields(self):
        data = self.client.post("/api/analyze", json={"text": "ERROR - boom"}).get_json()
        sc = data["scorecard"]
        for key in ("overall", "verdict", "verdict_blurb", "axes", "caps", "profile_label"):
            self.assertIn(key, sc)
            self.assertIn(key, self.js)

    def test_axis_fields(self):
        data = self.client.post("/api/analyze", json={"text": "ERROR - boom"}).get_json()
        for axis in data["scorecard"]["axes"]:
            for key in ("id", "label", "desc", "score", "weight"):
                self.assertIn(key, axis)

    def test_cluster_endpoint_fields(self):
        data = self.client.post("/api/cluster", json={"text": "boom"}).get_json()
        for key in ("total_occurrences", "distinct_signatures", "clusters", "insights",
                    "chokepoints"):
            self.assertIn(key, data)
            self.assertIn(key, self.js)

    def test_dom_ids_referenced_by_the_ui_exist_in_the_page(self):
        ids = set(re.findall(r'\$\("([a-z\-]+)"\)', self.js))
        html_ids = set(re.findall(r'id="([a-z\-]+)"', self.html))
        missing = sorted(ids - html_ids)
        self.assertEqual(missing, [], "the JS looks for elements that are not in the page")

    def test_tab_panels_exist(self):
        tabs = set(re.findall(r'data-tab="([a-z\-]+)"', self.html))
        panels = set(re.findall(r'id="tab-([a-z\-]+)"', self.html))
        self.assertTrue(tabs)
        self.assertEqual(tabs - panels, set())

    def test_static_assets_served(self):
        for path in ("/static/style.css", "/static/app.js"):
            res = self.client.get(path)
            self.assertEqual(res.status_code, 200)


if __name__ == "__main__":
    unittest.main()
