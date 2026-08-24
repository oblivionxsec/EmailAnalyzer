import json
import tempfile
import unittest
from pathlib import Path

from analyzer.cli.main import analyze
from analyzer.core.parser import parse_message
from analyzer.core.report_builder import build_report
from analyzer.core.local_tools import scan_report_attachments


class AnalyzerCoreTests(unittest.TestCase):
    def test_report_extracts_authentication_urls_and_score(self):
        raw = b"Authentication-Results: mx; spf=fail; dkim=pass\n\nVisit https://example.xyz/login"
        parsed = parse_message(raw)
        report = build_report(raw, parsed, processing_time_ms=1)
        self.assertEqual(report["authentication"]["spf"], "fail")
        self.assertEqual(report["content"]["urls"][0]["domain"], "example.xyz")
        self.assertEqual(report["scoring"]["score"], 65)

    def test_identity_and_urgency_rules_are_explainable(self):
        raw = b"From: Security Team <random@example.net>\nReply-To: inbox@other.example\nSubject: Action required\n\nVerify your account immediately"
        report = build_report(raw, parse_message(raw), processing_time_ms=1)
        rule_ids = {finding["id"] for finding in report["scoring"]["findings"]}
        self.assertTrue({"DISPLAY_NAME_SPOOF", "REPLY_TO_MISMATCH", "URGENT_LANGUAGE"}.issubset(rule_ids))

    def test_url_deception_signals_are_recorded(self):
        report = build_report(b"\nhttps://user:pass@xn--example-9za.com/login", parse_message(b"\nhttps://user:pass@xn--example-9za.com/login"), processing_time_ms=1)
        url = report["content"]["urls"][0]
        self.assertEqual(set(url["flags"]), {"userinfo", "punycode"})
        self.assertIn("URL_DECEPTION", {finding["id"] for finding in report["scoring"]["findings"]})

    def test_missing_authentication_is_absent(self):
        parsed = parse_message(b"Subject: No auth\n\nBody")
        self.assertEqual(parsed["authentication"], {"spf": "absent", "dkim": "absent", "dmarc": "absent"})

    def test_mislabeled_utf8_body_is_recovered(self):
        raw = b'Content-Type: text/plain; charset="Windows-1251"\n\nWe\xe2\x80\x99ve paid'
        self.assertIn("We\u2019ve paid", parse_message(raw)["plain_text"])

    def test_recursive_archive_finds_executable(self):
        import io
        import zipfile

        archive_data = io.BytesIO()
        with zipfile.ZipFile(archive_data, "w") as archive:
            archive.writestr("payload.exe", b"MZ")
        raw = (
            b"Content-Type: multipart/mixed; boundary=x\n\n--x\n"
            b"Content-Type: application/zip\nContent-Disposition: attachment; filename=outer.zip\n"
            b"Content-Transfer-Encoding: base64\n\n"
            + __import__("base64").b64encode(archive_data.getvalue())
            + b"\n--x--\n"
        )
        parsed = parse_message(raw)
        report = build_report(raw, parsed, processing_time_ms=1)
        self.assertEqual(parsed["attachments"][0]["children"][0]["filename"], "payload.exe")
        self.assertEqual(report["phishing_analysis"]["indicators"][0]["type"], "executable_attachment")
        self.assertEqual(report["scoring"]["category"], "Suspicious")

    def test_cli_writes_json_report(self):
        sample = Path(__file__).parents[2] / "samples" / "sample.eml"
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "report.json"
            report = analyze(sample, output)
            self.assertTrue(output.exists())
            self.assertEqual(json.loads(output.read_text())["meta"]["version"], "1.0.0")
            self.assertEqual(report["meta"]["source_name"], "sample.eml")
            self.assertGreaterEqual(report["email"]["raw_size_bytes"], 1)

    def test_cli_honors_no_intel_flag(self):
        sample = Path(__file__).parents[2] / "samples" / "sample.eml"
        with tempfile.TemporaryDirectory() as directory:
            report = analyze(sample, Path(directory) / "report.json", no_intel=True)
            self.assertEqual(report["threat_intel"]["mode"], "disabled")

    def test_local_tool_scan_removes_private_attachment_bytes(self):
        report = {"attachments": [{"filename": "note.txt", "_data": b"hello", "children": []}]}
        scan_report_attachments(report)
        self.assertNotIn("_data", report["attachments"][0])
        self.assertEqual(report["local_tools"]["scanned"], 1)


if __name__ == "__main__":
    unittest.main()
