import json
import tempfile
import unittest
from pathlib import Path

import prioritize

HERE = Path(__file__).parent
FIX = HERE / "fixtures"


class TriageTest(unittest.TestCase):
    def run_triage(self, fail_on=None):
        out = Path(tempfile.mkdtemp()) / "report.md"
        argv = ["--trivy", str(FIX / "trivy.json"),
                "--sarif", str(FIX / "semgrep.sarif"), str(FIX / "gitleaks.sarif"),
                "--offline", str(FIX), "--out", str(out)]
        if fail_on:
            argv += ["--fail-on", fail_on]
        code = prioritize.main(argv)
        return code, out.read_text()

    def findings(self):
        f = prioritize.load_trivy(FIX / "trivy.json") + prioritize.load_sarif(FIX / "semgrep.sarif") \
            + prioritize.load_sarif(FIX / "gitleaks.sarif")
        accepted = json.loads((HERE / "accepted.json").read_text())
        return {x["id"]: x for x in prioritize.triage(prioritize.enrich(f, FIX), accepted)}

    def test_kev_is_p1(self):
        self.assertEqual(self.findings()["CVE-2021-44228"]["priority"], "P1")

    def test_secret_is_p1(self):
        self.assertEqual(self.findings()["generic-api-key"]["priority"], "P1")

    def test_high_epss_not_in_kev_is_p2(self):
        self.assertEqual(self.findings()["CVE-2022-22965"]["priority"], "P2")

    def test_cvss_high_low_epss_is_p3(self):
        self.assertEqual(self.findings()["CVE-2023-0001"]["priority"], "P3")

    def test_low_is_p4(self):
        self.assertEqual(self.findings()["CVE-2023-0002"]["priority"], "P4")

    def test_accepted_false_positive_is_kept_and_marked(self):
        f = self.findings()["java.lang.security.audit.crypto.weak-hash"]
        self.assertIn("non-security cache key", f["accepted"])

    def test_report_orders_p1_first(self):
        _, report = self.run_triage()
        rows = [l for l in report.splitlines() if l.startswith("| P") and not l.startswith("| Priority")]
        self.assertTrue(rows[0].startswith("| P1"))
        self.assertIn("accepted", rows[-1])

    def test_zap_alert_is_parsed(self):
        f = prioritize.load_zap(FIX / "zap.json")[0]
        self.assertEqual((f["id"], f["kind"], f["severity"]), ("ZAP-10038", "dast", "MEDIUM"))

    def test_fail_on_p1_blocks_pipeline(self):
        code, _ = self.run_triage(fail_on="P1")
        self.assertEqual(code, 1)


if __name__ == "__main__":
    unittest.main()
