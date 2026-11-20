"""Engine tests for stacktrace-forge."""

import json
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from engine import analysis, cluster, export, parsers, scoring, taxonomy  # noqa: E402

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


class ParserTests(unittest.TestCase):
    def test_language_detection(self):
        cases = [
            ("java_npe_chain", "java"),
            ("node_secret_undefined", "javascript"),
            ("go_panic_recursion", "go"),
        ]
        for sample_id, lang in cases:
            detected = parsers.detect_language(sample_text(sample_id))
            self.assertEqual(detected, lang, sample_id)

    def test_java_chain_and_root_cause(self):
        parsed = parsers.parse_input(sample_text("java_npe_chain"))
        self.assertEqual(len(parsed["occurrences"]), 1)
        chain = parsed["occurrences"][0]["errors"]
        self.assertEqual(len(chain), 2)
        self.assertEqual(chain[0].error_type, "java.lang.NullPointerException")
        self.assertEqual(chain[1].error_type, "java.lang.IllegalStateException")
        self.assertEqual(chain[1].chain_marker, "Caused by")

    def test_java_frames_carry_file_and_line(self):
        parsed = parsers.parse_input(sample_text("java_npe_chain"))
        frame = parsed["occurrences"][0]["errors"][1].frames[0]
        self.assertEqual(frame.file, "ContractRepository.java")
        self.assertEqual(frame.line, 64)
        self.assertEqual(frame.origin, "app")
        self.assertTrue(frame.in_app)

    def test_go_panic_frames_parsed(self):
        parsed = parsers.parse_input(sample_text("go_panic_recursion"))
        errors = parsed["occurrences"][0]["errors"]
        self.assertEqual(len(errors), 1)
        self.assertEqual(len(errors[0].frames), 10)
        self.assertEqual(errors[0].frames[0].file, "/app/pool/worker.go")
        self.assertEqual(errors[0].frames[0].line, 142)

    def test_js_header_inside_log_prefix(self):
        parsed = parsers.parse_input(sample_text("node_secret_undefined"))
        errors = parsed["occurrences"][0]["errors"]
        self.assertEqual(errors[0].error_type, "TypeError")
        self.assertIn("undefined", errors[0].message)

    def test_python_traceback(self):
        block = (
            'Traceback (most recent call last):\n'
            '  File "/app/main.py", line 42, in run\n'
            "    value = payload['id']\n"
            "KeyError: 'id'\n"
        )
        errors = parsers.parse_error_block(block)
        self.assertEqual(len(errors), 1)
        self.assertEqual(errors[0].error_type, "KeyError")
        self.assertEqual(errors[0].frames[0].file, "/app/main.py")
        self.assertEqual(errors[0].frames[0].line, 42)

    def test_python_cause_chain(self):
        block = (
            "Traceback (most recent call last):\n"
            '  File "/app/main.py", line 10, in run\n'
            "    helper()\n"
            "ValueError: inner problem\n"
            "\n"
            "During handling of the above exception, another exception occurred:\n"
            "\n"
            "Traceback (most recent call last):\n"
            '  File "/app/main.py", line 12, in run\n'
            "    raise RuntimeError('wrapped')\n"
            "RuntimeError: wrapped\n"
        )
        errors = parsers.parse_error_block(block)
        self.assertEqual(len(errors), 2)
        self.assertEqual(errors[-1].error_type, "RuntimeError")

    def test_csharp_and_rust_and_php(self):
        cs = (
            "System.NullReferenceException: Object reference not set to an instance of an object.\n"
            "   at MyApp.Worker.Run() in C:\\src\\Worker.cs:line 42\n"
        )
        errs = parsers.parse_error_block(cs)
        self.assertEqual(errs[0].language, "csharp")
        self.assertEqual(errs[0].frames[0].line, 42)

        rs = (
            "thread 'main' panicked at src/parser.rs:42:5:\n"
            "called \x60Option::unwrap()\x60 on a \x60None\x60 value\n"
        )
        errs = parsers.parse_error_block(rs)
        self.assertEqual(errs[0].language, "rust")
        self.assertEqual(errs[0].frames[0].file, "src/parser.rs")

        php = "PHP Fatal error:  Uncaught TypeError: foo(): Argument #1 must be of type int in /var/www/index.php:12\n"
        errs = parsers.parse_error_block(php)
        self.assertEqual(errs[0].language, "php")

    def test_ruby_error(self):
        block = ("undefined method \x60name' for nil:NilClass (NoMethodError)\n"
                 "\tfrom (irb):1:in \x60<main>'\n")
        errs = parsers.parse_error_block(block)
        self.assertEqual(errs[0].language, "ruby")
        self.assertEqual(errs[0].error_type, "NoMethodError")

    def test_log_entries_need_level_or_timestamp(self):
        logs = parsers.parse_logs(sample_text("go_panic_recursion"))
        self.assertEqual(len(logs), 0)
        logs = parsers.parse_logs(sample_text("java_npe_chain"))
        self.assertGreaterEqual(len(logs), 1)
        self.assertEqual(logs[0].level, "ERROR")

    def test_two_segment_package_is_application_code(self):
        block = ("java.lang.NullPointerException: customer is null\n"
                 "\tat com.acme.OrderService.applyTier(OrderService.java:142)\n")
        errors = parsers.parse_error_block(block)
        frame = errors[0].frames[0]
        self.assertEqual(frame.origin, "app")
        self.assertTrue(frame.in_app)

    def test_frameless_java_exception_is_detected(self):
        detected = parsers.detect_language("java.lang.NullPointerException: customer is null")
        self.assertEqual(detected, "java")

    def test_occurrence_splitting_on_dashes(self):
        parsed = parsers.parse_input(sample_text("repeated_occurrences"))
        self.assertEqual(parsed["occurrence_count"], 5)


class TaxonomyTests(unittest.TestCase):
    def test_every_category_has_hypotheses(self):
        for cat in taxonomy.CATEGORIES:
            self.assertTrue(cat["hypotheses"], cat["id"])
            for h in cat["hypotheses"]:
                self.assertTrue(h["cause"])
                self.assertTrue(h["check"])
                self.assertGreaterEqual(h["weight"], 1)

    def test_match_category(self):
        cat = taxonomy.match_category("java.lang.NullPointerException: cannot invoke")
        self.assertEqual(cat["id"], "null_reference")
        cat = taxonomy.match_category("java.sql.SQLException: relation does not exist")
        self.assertEqual(cat["id"], "database")
        cat = taxonomy.match_category("something entirely bespoke")
        self.assertEqual(cat["id"], "unknown")

    def test_all_patterns_compile(self):
        import re
        for cat in taxonomy.CATEGORIES:
            for pat in cat["patterns"]:
                re.compile(pat)


class AnalysisTests(unittest.TestCase):
    def test_shape_of_result(self):
        res = analysis.analyze(sample_text("java_npe_chain"))
        for key in ("meta", "primary", "chain", "classification", "hypotheses", "findings",
                    "red_flags", "triage", "repro", "message_quality", "scorecard",
                    "fix_plan", "logs"):
            self.assertIn(key, res)

    def test_findings_are_well_formed(self):
        valid_axes = set(scoring.AXIS_IDS)
        for s in SAMPLE_INDEX:
            res = analysis.analyze(sample_text(s["id"]))
            for f in res["findings"]:
                for key in ("id", "axis", "severity", "title", "evidence", "why_it_matters", "fix"):
                    self.assertTrue(f[key], s["id"] + " " + f.get("id", "") + " missing " + key)
                self.assertIn(f["axis"], valid_axes)
                self.assertIn(f["severity"], ("critical", "high", "medium", "low"))

    def test_hypotheses_are_ranked_with_checks(self):
        res = analysis.analyze(sample_text("java_npe_chain"))
        self.assertGreaterEqual(len(res["hypotheses"]), 3)
        for i, h in enumerate(res["hypotheses"]):
            self.assertEqual(h["rank"], i + 1)
            self.assertTrue(h["check"])
            self.assertIn(h["likelihood"], ("high", "medium", "low"))
        weights = [h["weight"] for h in res["hypotheses"]]
        self.assertEqual(weights, sorted(weights, reverse=True))

    def test_triage_steps_are_sequential(self):
        res = analysis.analyze(sample_text("java_generic_wrapper"))
        steps = [s["step"] for s in res["triage"]]
        self.assertEqual(steps, list(range(1, len(steps) + 1)))
        self.assertTrue(all(s["timebox"] for s in res["triage"]))

    def test_scores_are_bounded(self):
        for s in SAMPLE_INDEX:
            res = analysis.analyze(sample_text(s["id"]))
            sc = res["scorecard"]
            self.assertGreaterEqual(sc["overall"], 0)
            self.assertLessEqual(sc["overall"], 100)
            for axis in sc["axes"]:
                self.assertGreaterEqual(axis["score"], 0)
                self.assertLessEqual(axis["score"], 100)

    def test_control_sample_scores_high_and_floor_sample_low(self):
        good = analysis.analyze(sample_text("java_npe_chain"))
        bad = analysis.analyze(sample_text("log_vague_no_trace"))
        self.assertGreaterEqual(good["scorecard"]["overall"], 85)
        self.assertLessEqual(bad["scorecard"]["overall"], 45)
        self.assertEqual(good["scorecard"]["verdict"], "diagnosable")
        self.assertEqual(bad["scorecard"]["verdict"], "not_diagnosable")

    def test_secret_sample_raises_a_critical_finding(self):
        res = analysis.analyze(sample_text("node_secret_undefined"))
        ids = [f["id"] for f in res["findings"]]
        self.assertIn("secret_in_log", ids)
        secret = [f for f in res["findings"] if f["id"] == "secret_in_log"][0]
        self.assertEqual(secret["severity"], "critical")

    def test_recursive_frames_detected(self):
        res = analysis.analyze(sample_text("go_panic_recursion"))
        ids = [f["id"] for f in res["findings"]]
        self.assertIn("recursive_frames", ids)

    def test_origin_frame_points_at_application_code(self):
        res = analysis.analyze(sample_text("java_npe_chain"))
        origin = res["primary"]["origin_frame"]
        self.assertIsNotNone(origin)
        self.assertTrue(origin["in_app"])
        self.assertEqual(origin["location"], "ContractRepository.java:64")

    def test_unknown_category_caps_the_overall_score(self):
        res = analysis.analyze(sample_text("java_generic_wrapper"))
        caps = res["scorecard"]["caps"]
        self.assertTrue(any("known error class" in c["reason"] for c in caps))
        self.assertLessEqual(res["scorecard"]["overall"], 62)

    def test_empty_input_is_handled(self):
        res = analysis.analyze("")
        self.assertEqual(res["scorecard"]["overall"], 0)
        self.assertEqual(res["scorecard"]["verdict"], "not_diagnosable")

    def test_profiles_change_the_weighting(self):
        a = analysis.analyze(sample_text("java_npe_chain"), profile="incident")
        b = analysis.analyze(sample_text("java_npe_chain"), profile="postmortem")
        self.assertNotEqual(a["scorecard"]["weights"], b["scorecard"]["weights"])
        self.assertEqual(a["scorecard"]["profile"], "incident")

    def test_fix_plan_is_ranked(self):
        res = analysis.analyze(sample_text("node_secret_undefined"))
        plan = res["fix_plan"]
        self.assertGreaterEqual(len(plan), 1)
        self.assertEqual(plan[0]["rank"], 1)
        self.assertEqual(plan[0]["kind"], "investigate")

    def test_repro_skeleton_mentions_the_location(self):
        res = analysis.analyze(sample_text("java_npe_chain"))
        self.assertIn("ContractRepository.java:64", res["repro"]["skeleton"])


class ClusterTests(unittest.TestCase):
    def test_identical_occurrences_collapse(self):
        res = cluster.cluster_occurrences(sample_text("repeated_occurrences"))
        self.assertEqual(res["total_occurrences"], 5)
        self.assertEqual(res["distinct_signatures"], 3)
        self.assertEqual(res["clusters"][0]["count"], 3)
        self.assertGreater(res["clusters"][0]["share"], 50)

    def test_insights_are_produced(self):
        res = cluster.cluster_occurrences(sample_text("repeated_occurrences"))
        kinds = [i["kind"] for i in res["insights"]]
        self.assertIn("dominant", kinds)

    def test_single_occurrence(self):
        res = cluster.cluster_occurrences(sample_text("java_npe_chain"))
        self.assertEqual(res["total_occurrences"], 1)
        self.assertEqual(res["distinct_signatures"], 1)


class ExportTests(unittest.TestCase):
    def setUp(self):
        self.result = analysis.analyze(sample_text("java_npe_chain"))

    def test_markdown_export(self):
        md = export.to_markdown(self.result)
        self.assertIn("# stacktrace-forge triage report", md)
        self.assertIn("## Ranked hypotheses", md)
        self.assertIn("## Triage checklist", md)

    def test_json_export_round_trips(self):
        data = json.loads(export.to_json(self.result))
        self.assertEqual(data["scorecard"]["overall"], self.result["scorecard"]["overall"])

    def test_csv_export(self):
        csv_text = export.to_csv(self.result)
        lines = csv_text.strip().split("\n")
        self.assertTrue(lines[0].startswith("kind,rank"))
        self.assertGreater(len(lines), 1)


if __name__ == "__main__":
    unittest.main()
