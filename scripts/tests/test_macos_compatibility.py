import importlib.util
import json
from pathlib import Path
import plistlib
import struct
import sys
import tempfile
from types import SimpleNamespace
import unittest

SCRIPTS = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(SCRIPTS))
from macos_compatibility import CPU_TYPES, verify_binary

SPEC = importlib.util.spec_from_file_location("portable_macos", SCRIPTS / "package-portable.py")
portable = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(portable)


def executable(target, major, legacy=False):
    command = (struct.pack("<4I", 0x24, 16, major << 16, 0) if legacy
               else struct.pack("<6I", 0x32, 24, 1, major << 16, 0, 0))
    return struct.pack("<8I", 0xFEEDFACF, CPU_TYPES[target], 0, 2, 1, len(command), 0, 0) + command


class MacOsCompatibilityTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.target = "x86_64-apple-darwin"

    def test_binary_rejects_newer_system_wrong_cpu_and_truncated_commands(self):
        binary = self.root / "sing-box-acp"
        for legacy in (False, True):
            binary.write_bytes(executable(self.target, 12, legacy))
            self.assertEqual(verify_binary(binary, self.target), "12.0.0")
            binary.write_bytes(executable(self.target, 13, legacy))
            with self.assertRaisesRegex(RuntimeError, "requires macOS 13"):
                verify_binary(binary, self.target)
        binary.write_bytes(executable("aarch64-apple-darwin", 12))
        with self.assertRaisesRegex(RuntimeError, "architecture"):
            verify_binary(binary, self.target)
        binary.write_bytes(executable(self.target, 12)[:-1])
        with self.assertRaisesRegex(RuntimeError, "truncated"):
            verify_binary(binary, self.target)

    def test_app_minimum_matches_architecture_and_every_bundled_executable(self):
        for target, major in ((self.target, 12), ("aarch64-apple-darwin", 13)):
            with self.subTest(target=target):
                build = self.root / target
                build.mkdir()
                core = build / "sing-box-acp"
                names = ("topnode-desktop", "sing-box-acp", "topnode-network-daemon",
                         "topnode-network-bridge", "topnode-proxy-settings")
                for name in names:
                    (build / name).write_bytes(executable(target, major))
                (build / "source.json").write_text(json.dumps({"libraries": []}))
                (build / "LICENSE.sing-box-acp").write_text("test fixture")
                args = SimpleNamespace(target=target, application=build / "topnode-desktop",
                                       core_build=build, support_build=build, version_name="1.0.0",
                                       version_code=1, signing_identity=None, candidate=True)
                payload = build / "payload"
                portable.assemble_payload(payload, args, core)
                with (payload / "TOPNODE Desktop.app/Contents/Info.plist").open("rb") as stream:
                    self.assertEqual(plistlib.load(stream)["LSMinimumSystemVersion"], f"{major}.0")
                for name in names:
                    (build / name).write_bytes(executable(target, major + 1))
                    with self.assertRaisesRegex(RuntimeError, f"{name}: requires macOS"):
                        portable.assemble_payload(build / ("rejected-" + name), args, core)
                    (build / name).write_bytes(executable(target, major))


if __name__ == "__main__":
    unittest.main()
