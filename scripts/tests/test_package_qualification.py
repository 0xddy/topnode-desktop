import importlib.util
import json
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
import unittest

SCRIPTS = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(SCRIPTS))
SPEC = importlib.util.spec_from_file_location("portable", SCRIPTS / "package-portable.py")
portable = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(portable)


class PackageQualificationTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.core = self.root / "core/sing-box-acp.exe"
        self.core.parent.mkdir()
        self.core.write_bytes(b"unit-test-only-core")
        library = self.core.parent / "libcronet.dll"
        library.write_bytes(b"unit-test-only-library")
        lock = dict(line.split("=", 1) for line in (portable.ROOT / "config/sing-box-acp.lock").read_text().splitlines())
        self.metadata = {"repository": lock["repository"], "version": lock["version"], "commit": lock["commit"],
                         "goVersion": lock["go"], "target": "x86_64-pc-windows-msvc", "goos": "windows",
                         "nativeCheck": False, "binarySha256": portable.sha256_file(self.core),
                         "tags": ["with_naive_outbound"], "libraries": [{"file":library.name,"sha256":portable.sha256_file(library)}]}
        (self.root / "source.json").write_text(json.dumps(self.metadata))

    def test_candidate_cannot_be_promoted_without_native_execution_and_report(self):
        portable.validate_core_build(self.root, self.metadata["target"], candidate=True)
        with self.assertRaisesRegex(RuntimeError, "native execution"):
            portable.validate_core_build(self.root, self.metadata["target"])
        self.metadata["nativeCheck"] = True
        (self.root / "source.json").write_text(json.dumps(self.metadata))
        with self.assertRaises(FileNotFoundError):
            portable.validate_core_build(self.root, self.metadata["target"])

    def test_even_candidate_rejects_changed_core_or_library_escape(self):
        self.core.write_bytes(b"replaced")
        with self.assertRaisesRegex(RuntimeError, "metadata"):
            portable.validate_core_build(self.root, self.metadata["target"], candidate=True)
        self.metadata["binarySha256"] = portable.sha256_file(self.core)
        self.metadata["libraries"].append({"file": "../escape", "sha256": "0" * 64})
        (self.root / "source.json").write_text(json.dumps(self.metadata))
        with self.assertRaisesRegex(RuntimeError, "filename"):
            portable.validate_core_build(self.root, self.metadata["target"], candidate=True)

    def test_system_report_binds_helper_and_requires_full_matrix(self):
        app = self.root / "app"
        app.write_bytes(b"fixture-app")
        helper = self.root / "topnode-net-helper"
        helper.write_bytes(b"fixture-helper")
        report = self.root / "system.json"
        args = SimpleNamespace(system_acceptance=report, target="x86_64-unknown-linux-gnu", application=app, support_build=self.root)
        data = {"schema_version": 1, "target": args.target, "application_sha256": portable.sha256_file(app),
                "core_sha256": portable.sha256_file(self.core), "helpers": {helper.name: portable.sha256_file(helper)},
                "checks": {key: True for key in ("system_proxy", "tun_udp", "udp_disabled", "dns_detour", "permission_denied", "process_exit_cleanup", "external_proxy_change", "network_switch", "sleep_wake", "upgrade", "uninstall")},
                "soak_seconds": 3600, "mixed_traffic_seconds": 1800, "connection_cycles": 100}
        report.write_text(json.dumps(data))
        portable.validate_system_acceptance(args, self.core)
        helper.write_bytes(b"replacement")
        with self.assertRaisesRegex(RuntimeError, "helper"):
            portable.validate_system_acceptance(args, self.core)


if __name__ == "__main__":
    unittest.main()
