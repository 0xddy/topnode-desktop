"""Exercise publication and retry behavior without contacting GitHub."""

import importlib.util
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from test_publish_dufs import CODE, COMMIT, DIRECTORY, SOURCE_RUN_ID, VERSION, write_assets


SPEC = importlib.util.spec_from_file_location(
    "publish_github_release", Path(__file__).parents[1] / "publish-github-release.py",
)
publisher = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(publisher)


class MemoryGitHub:
    repository = "example/desktop"

    def __init__(self):
        self.current = None
        self.tag_commit = None
        self.files = {}
        self.calls = []
        self.notes = ""
        self.corrupt_downloads = False
        self.fail_upload = False

    def api(self, path, *, missing_ok=False):
        if path == f"releases/tags/{DIRECTORY}":
            return self.current
        if path == f"git/ref/tags/{DIRECTORY}":
            if self.tag_commit is not None:
                return {"object": {"type": "commit", "sha": self.tag_commit}}
            if missing_ok:
                return None
        raise AssertionError(f"Unexpected API request: {path}")

    def release(self, *arguments):
        self.calls.append(arguments)
        command, tag, *options = arguments
        assert tag == DIRECTORY
        if command in ("create", "edit"):
            if command == "create":
                assert self.current is None
                self.current = {"draft": True}
            if "--target" in options:
                self.current["target_commitish"] = options[options.index("--target") + 1]
            if "--notes-file" in options:
                self.notes = Path(options[options.index("--notes-file") + 1]).read_text(encoding="utf-8")
            if "--draft=false" in options:
                self.current["draft"] = False
                self.tag_commit = self.current["target_commitish"]
        elif command == "upload":
            assert self.current["draft"], "Published assets must never be overwritten"
            for filename in options:
                if filename != "--clobber":
                    path = Path(filename)
                    self.files[path.name] = path.read_bytes()
                    if self.fail_upload:
                        raise subprocess.CalledProcessError(1, "gh release upload")
        elif command == "download":
            directory = Path(options[options.index("--dir") + 1])
            for name, content in self.files.items():
                (directory / name).write_bytes(content + (b"corrupt" if self.corrupt_downloads else b""))
        else:
            raise AssertionError(f"Unexpected release operation: {command}")


class GitHubPublisherTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.assets = Path(temporary.name)
        write_assets(self.assets, application_override={"supportTier": "candidate"})
        for platform in ("linux-x86_64", "linux-aarch64"):
            (self.assets / f"topnode-desktop-{VERSION}-{platform}.deb").write_bytes(b"installer")
        self.client = MemoryGitHub()

    def publish(self):
        return publisher.publish(self.client, self.assets, CODE, VERSION, COMMIT, "1.14.4-test", SOURCE_RUN_ID)

    def test_publishes_nine_verified_assets_as_prerelease_after_download(self):
        url = self.publish()
        self.assertEqual(url, f"https://github.com/example/desktop/releases/tag/{DIRECTORY}")
        self.assertEqual(len(self.client.files), 9)
        self.assertEqual(self.client.tag_commit, COMMIT)
        self.assertFalse(self.client.current["draft"])
        self.assertEqual([call[0] for call in self.client.calls], ["create", "upload", "download", "edit"])
        self.assertIn("--prerelease", self.client.calls[-1])
        self.assertIn("--latest=false", self.client.calls[-1])
        self.assertIn("macOS 12.7.6 runtime testing has not been completed", self.client.notes)
        self.assertIn(f"actions/runs/{SOURCE_RUN_ID}", self.client.notes)
        self.assertEqual(len(self.client.files["SHA256SUMS.txt"].splitlines()), 8)

    def test_published_retry_verifies_without_mutating_release(self):
        self.publish()
        self.client.calls.clear()
        self.publish()
        self.assertEqual([call[0] for call in self.client.calls], ["download"])

    def test_incomplete_upload_stays_draft_and_can_be_retried(self):
        self.client.fail_upload = True
        with self.assertRaises(subprocess.CalledProcessError):
            self.publish()
        self.assertTrue(self.client.current["draft"])
        self.assertEqual(len(self.client.files), 1)
        self.client.fail_upload = False
        self.publish()
        self.assertFalse(self.client.current["draft"])
        self.assertEqual(len(self.client.files), 9)

    def test_corrupt_download_does_not_publish_draft(self):
        self.client.corrupt_downloads = True
        with self.assertRaisesRegex(publisher.PublishError, "differs"):
            self.publish()
        self.assertTrue(self.client.current["draft"])

    def test_published_different_bytes_are_never_overwritten(self):
        self.publish()
        self.client.calls.clear()
        self.client.files["SHA256SUMS.txt"] = b"different build"
        with self.assertRaisesRegex(publisher.PublishError, "differs"):
            self.publish()
        self.assertEqual([call[0] for call in self.client.calls], ["download"])
        self.assertEqual(self.client.files["SHA256SUMS.txt"], b"different build")

    def test_conflicting_existing_tag_is_rejected_before_creation(self):
        self.client.tag_commit = "b" * 40
        with self.assertRaisesRegex(publisher.PublishError, "tag targets a different"):
            self.publish()
        self.assertEqual(self.client.calls, [])

    def test_wrong_draft_target_is_not_modified(self):
        self.client.current = {"draft": True, "target_commitish": "b" * 40}
        with self.assertRaisesRegex(publisher.PublishError, "draft targets a different"):
            self.publish()
        self.assertEqual(self.client.calls, [])

    def test_missing_package_is_rejected_before_creation(self):
        next(self.assets.glob("*.deb")).unlink()
        with self.assertRaisesRegex(publisher.PublishError, "Expected exactly"):
            self.publish()
        self.assertEqual(self.client.calls, [])
        self.assertIsNone(self.client.current)

    def test_unexpected_draft_asset_prevents_publication(self):
        self.client.files["unexpected.zip"] = b"another build"
        with self.assertRaisesRegex(publisher.PublishError, "exactly the eight packages"):
            self.publish()
        self.assertTrue(self.client.current["draft"])

    def test_api_does_not_treat_authentication_failure_as_missing_release(self):
        client = publisher.GitHub("example/desktop")
        with patch.object(publisher.subprocess, "run", return_value=subprocess.CompletedProcess(
                [], 1, "", "gh: Bad credentials (HTTP 401)")):
            with self.assertRaisesRegex(publisher.PublishError, "API request failed"):
                client.api("releases/tags/example", missing_ok=True)
        with patch.object(publisher.subprocess, "run", return_value=subprocess.CompletedProcess(
                [], 1, "", "gh: Not Found (HTTP 404)")):
            self.assertIsNone(client.api("releases/tags/example", missing_ok=True))

    def test_annotated_tag_is_resolved_to_commit(self):
        with patch.object(self.client, "api", side_effect=[
            {"object": {"type": "tag", "sha": "b" * 40}},
            {"object": {"type": "commit", "sha": COMMIT}},
        ]):
            publisher.check_tag(self.client, DIRECTORY, COMMIT, required=True)


if __name__ == "__main__":
    unittest.main()
