import unittest

from app.models import RiskLevel
from app.scanner import scan_attachment
from tests import samples


class PdfTests(unittest.TestCase):
    def test_spec_scenario_hdfc_pdf_is_high_threat(self):
        data = samples.pdf_with_link("http://hdfc-login-update.xyz")
        r = scan_attachment("HDFC_Security_Update.pdf", data)
        self.assertTrue(r.attachment_scanned)
        self.assertTrue(r.has_malicious_form)
        self.assertEqual(r.attachment_risk_level, RiskLevel.HIGH_THREAT)
        self.assertIn("http://hdfc-login-update.xyz", r.suspicious_links)

    def test_clean_pdf_with_official_link_is_safe(self):
        r = scan_attachment("statement.pdf", samples.pdf_clean())
        self.assertEqual(r.attachment_risk_level, RiskLevel.SAFE)
        self.assertFalse(r.has_malicious_form)

    def test_pdf_javascript_detected(self):
        r = scan_attachment("invoice.pdf", samples.pdf_with_javascript())
        self.assertTrue(r.has_malicious_script)
        self.assertGreaterEqual(r.attachment_risk_level.rank, RiskLevel.LOW_RISK.rank)

    def test_corrupt_pdf_falls_back_to_raw_scan(self):
        r = scan_attachment("x.pdf", b"%PDF-1.4\n/OpenAction /JavaScript http://bad-login.xyz/a\n garbage")
        self.assertTrue(r.attachment_scanned)
        self.assertTrue(any(f.code == "MALFORMED_PDF" for f in r.findings))
        self.assertTrue(r.has_malicious_script)


class HtmlTests(unittest.TestCase):
    def test_external_credential_form(self):
        r = scan_attachment("update.html", samples.PHISHING_HTML)
        self.assertTrue(r.has_malicious_form)
        self.assertEqual(r.attachment_risk_level, RiskLevel.HIGH_THREAT)

    def test_obfuscated_exfiltration_script(self):
        r = scan_attachment("doc.html", samples.OBFUSCATED_HTML)
        self.assertTrue(r.has_malicious_script)
        self.assertTrue(r.has_malicious_form)       # password field with no real action
        self.assertEqual(r.attachment_risk_level, RiskLevel.HIGH_THREAT)

    def test_clean_html_is_safe(self):
        r = scan_attachment("news.html", samples.CLEAN_HTML)
        self.assertEqual(r.attachment_risk_level, RiskLevel.SAFE)

    def test_deceptive_link_text(self):
        r = scan_attachment("a.html", samples.DECEPTIVE_HTML)
        self.assertTrue(any(f.code == "DECEPTIVE_LINK" for f in r.findings))


class EdgeCaseTests(unittest.TestCase):
    def test_html_disguised_as_pdf(self):
        r = scan_attachment("Invoice.pdf", samples.PHISHING_HTML)
        self.assertEqual(r.file_type, "html")
        self.assertTrue(any(f.code == "EXTENSION_MISMATCH" for f in r.findings))

    def test_unsupported_type_not_scanned(self):
        r = scan_attachment("photo.png", b"\x89PNG\r\n")
        self.assertFalse(r.attachment_scanned)

    def test_path_traversal_in_name_is_stripped(self):
        r = scan_attachment("../../etc/passwd.html", samples.CLEAN_HTML)
        self.assertEqual(r.file_name, "passwd.html")

    def test_oversized_file_fails_closed(self):
        r = scan_attachment("big.pdf", b"%PDF-" + b"0" * (10 * 1024 * 1024))
        self.assertFalse(r.attachment_scanned)
        self.assertEqual(r.attachment_risk_level, RiskLevel.SUSPICIOUS)


if __name__ == "__main__":
    unittest.main()
