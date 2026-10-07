import asyncio
import json
import time
import unittest

from app.models import RiskLevel, TextReport
from app.nlp import HeuristicTextAnalyzer
from app.pipeline import Pipeline
from tests import samples


class SlowAnalyzer:
    def analyze(self, subject, body):
        time.sleep(3)
        return TextReport()


class BrokenAnalyzer:
    def analyze(self, subject, body):
        raise RuntimeError("model not loaded")


def run(pipeline, subject, body, files):
    return asyncio.run(pipeline.run(subject, body, files))


class PipelineTests(unittest.TestCase):
    def setUp(self):
        self.pipeline = Pipeline(HeuristicTextAnalyzer())

    def tearDown(self):
        self.pipeline.close()

    def test_unified_json_matches_spec_fields(self):
        files = [("HDFC_Security_Update.pdf", samples.pdf_with_link("http://hdfc-login-update.xyz"))]
        res = run(self.pipeline, "Urgent: verify your account", "Your account will be suspended. Click here.", files)
        payload = json.loads(res.model_dump_json())
        self.assertTrue(payload["attachment_scanned"])
        self.assertEqual(payload["file_name"], "HDFC_Security_Update.pdf")
        self.assertTrue(payload["has_malicious_form"])
        self.assertEqual(payload["attachment_risk_level"], "HIGH_THREAT")
        self.assertEqual(payload["overall_risk_level"], "HIGH_THREAT")

    def test_text_only_email(self):
        res = run(self.pipeline, "Lunch?", "Are we still on for noon?", [])
        self.assertFalse(res.attachment_scanned)
        self.assertEqual(res.overall_risk_level, RiskLevel.SAFE)

    def test_under_budget_with_several_attachments(self):
        files = [
            ("a.pdf", samples.pdf_with_link("http://hdfc-login-update.xyz")),
            ("b.html", samples.PHISHING_HTML),
            ("c.html", samples.OBFUSCATED_HTML),
            ("d.pdf", samples.pdf_clean()),
        ]
        res = run(self.pipeline, "Update", "Please verify your account", files)
        self.assertTrue(res.within_budget, f"took {res.total_ms} ms")
        self.assertLess(res.total_ms, 1500)

    def test_slow_analyzer_cannot_break_the_budget(self):
        p = Pipeline(SlowAnalyzer())
        try:
            res = run(p, "s", "b", [("n.html", samples.CLEAN_HTML)])
        finally:
            p.close()
        self.assertLess(res.total_ms, 1500)
        self.assertIn("timed out", res.text_analysis.error)
        self.assertEqual(res.attachments[0].attachment_risk_level, RiskLevel.SAFE)

    def test_crashing_analyzer_is_contained(self):
        p = Pipeline(BrokenAnalyzer())
        try:
            res = run(p, "s", "b", [("n.html", samples.PHISHING_HTML)])
        finally:
            p.close()
        self.assertIn("model not loaded", res.text_analysis.error)
        self.assertEqual(res.overall_risk_level, RiskLevel.HIGH_THREAT)


if __name__ == "__main__":
    unittest.main()
