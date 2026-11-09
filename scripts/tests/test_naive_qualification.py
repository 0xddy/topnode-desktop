"""A release must not outlive or overstate the native artifacts it tested."""
import copy
import json
from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from naive_qualification import CAPABILITIES, CHECKS, sha256, validate_report


class QualificationTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        self.core = self.root / "sing-box-acp.exe"
        self.core.write_bytes(b"native-core-test-fixture")
        library = self.root / "libcronet.dll"
        library.write_bytes(b"native-library-test-fixture")
        self.metadata = {"version": "1.14.4-fixture", "commit": "a" * 40,
                         "goos": "windows", "target": "aarch64-pc-windows-msvc",
                         "libraries": [{"file": library.name, "sha256": sha256(library)}]}
        self.report = {"schema_version": 2, "core_version": self.metadata["version"],
                       "core_commit": self.metadata["commit"], "target": self.metadata["target"],
                       "core_sha256": sha256(self.core), "libraries": self.metadata["libraries"],
                       "capabilities": sorted(CAPABILITIES),
                       "results": [dict(capability=cap, **{check: True for check in CHECKS}) for cap in CAPABILITIES]}

    def validate(self, report=None):
        (self.root / "naive-validation.json").write_text(json.dumps(report or self.report), encoding="utf-8")
        return validate_report(self.core, self.metadata)

    def test_exact_artifact_and_matrix(self):
        self.assertEqual(set(self.validate()["capabilities"]), CAPABILITIES)

    def test_core_or_library_replacement_invalidates_report(self):
        self.core.write_bytes(b"replaced")
        with self.assertRaises(ValueError):
            self.validate()
        self.report["core_sha256"] = sha256(self.core)
        (self.root / "libcronet.dll").write_bytes(b"replaced")
        with self.assertRaises(ValueError):
            self.validate()

    def test_wrong_abi_commit_or_old_schema_rejected(self):
        for field, value in (("schema_version", 1), ("core_commit", "b" * 40), ("target", "x86_64-pc-windows-msvc")):
            report = copy.deepcopy(self.report)
            report[field] = value
            with self.assertRaises(ValueError):
                self.validate(report)

    def test_http_only_and_missing_matrix_rejected(self):
        for check in CHECKS:
            report = copy.deepcopy(self.report)
            report["results"][0][check] = False
            with self.assertRaises(ValueError):
                self.validate(report)
        report = copy.deepcopy(self.report)
        report["capabilities"].pop()
        with self.assertRaises(ValueError):
            self.validate(report)

    def test_dependency_cannot_escape_install_directory(self):
        self.metadata["libraries"][0]["file"] = "../libcronet.dll"
        with self.assertRaises(ValueError):
            self.validate()


if __name__ == "__main__":
    unittest.main()
