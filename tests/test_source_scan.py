"""AgentShield source-scan tests — offline, no network, no code execution.

    python -m unittest discover -s tests -v
"""
import os
import sys
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
from agentshield import scan_source       # noqa: E402

SRC = os.path.join(ROOT, "samples", "source")


class TestVulnerablePython(unittest.TestCase):
    def setUp(self):
        self.rep, self.files = scan_source(os.path.join(SRC, "vulnerable_server.py"))

    def ids(self):
        return {f.id for f in self.rep.findings}

    def test_scanned_one_file(self):
        self.assertEqual(self.files, 1)

    def test_detects_command_injection(self):
        self.assertIn("AS-SRC-CMD-001", self.ids())

    def test_detects_shell_true(self):
        self.assertIn("AS-SRC-CMD-002", self.ids())

    def test_detects_prefix_path_escape(self):
        self.assertIn("AS-SRC-PATH-001", self.ids())

    def test_detects_ssrf(self):
        self.assertIn("AS-SRC-SSRF-001", self.ids())

    def test_detects_token_passthrough(self):
        self.assertIn("AS-SRC-TOKEN-001", self.ids())

    def test_detects_eval(self):
        self.assertIn("AS-SRC-EVAL-001", self.ids())

    def test_all_findings_are_indicators(self):
        # honesty: static source matches are never "confirmed"
        self.assertTrue(self.rep.findings)
        self.assertTrue(all(f.confidence == "indicator" for f in self.rep.findings))

    def test_where_has_file_and_line(self):
        for f in self.rep.findings:
            self.assertIn(":", f.where)   # file:line


class TestVulnerableJS(unittest.TestCase):
    def setUp(self):
        self.rep, _ = scan_source(os.path.join(SRC, "vulnerable_server.js"))

    def ids(self):
        return {f.id for f in self.rep.findings}

    def test_js_command_injection(self):
        self.assertIn("AS-SRC-CMD-001", self.ids())

    def test_js_prefix_and_ssrf(self):
        self.assertIn("AS-SRC-PATH-001", self.ids())
        self.assertIn("AS-SRC-SSRF-001", self.ids())


class TestCleanPython(unittest.TestCase):
    def test_clean_server_has_no_findings(self):
        rep, files = scan_source(os.path.join(SRC, "clean_server.py"))
        self.assertEqual(files, 1)
        self.assertEqual(rep.findings, [], f"clean server should be clean, got: "
                         f"{[f.id for f in rep.findings]}")


class TestDirectoryScan(unittest.TestCase):
    def test_scan_directory_counts_files(self):
        rep, files = scan_source(SRC)
        self.assertGreaterEqual(files, 3)          # .py x2 + .js x1
        self.assertTrue(rep.findings)              # the vulnerable ones trip rules


if __name__ == "__main__":
    unittest.main(verbosity=2)
