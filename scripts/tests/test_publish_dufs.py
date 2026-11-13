"""Publication tests use an in-memory HTTP service and never contact dufs."""

import base64
import importlib.util
import io
import json
from pathlib import Path
import tarfile
import tempfile
import unittest
from unittest.mock import patch
from urllib.error import HTTPError
from urllib.parse import urlsplit
import zipfile


SPEC = importlib.util.spec_from_file_location("publish_dufs", Path(__file__).parents[1] / "publish-dufs.py")
publisher = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(publisher)
COMMIT = "01234567" + "a" * 32
VERSION = "2026.09.08-01234567"
CODE = 11
DIRECTORY = f"desktop-v{CODE}-{VERSION}"
RELEASE_PATH = publisher.ROOT + DIRECTORY + "/"
SOURCE_RUN_ID = "12345"
CANDIDATE_PATH = publisher.CANDIDATE_ROOT + f"{DIRECTORY}-run-{SOURCE_RUN_ID}/"


def write_assets(directory, *, wrong_target=False, application_override=None):
    for platform, (target, extension) in publisher.PLATFORMS.items():
        stem = f"topnode-desktop-{VERSION}-{platform}"
        manifest_data = {
            "schemaVersion": 1,
            "application": {"versionCode": CODE, "versionName": VERSION,
                            "gitCommit": COMMIT, "supportTier": "supported", "target": "wrong" if wrong_target else target},
        }
        manifest_data["application"].update(application_override or {})
        manifest = json.dumps(manifest_data).encode()
        members = {stem + "/BUILD-INFO.json": manifest, stem + "/payload": b"binary-payload\x00\xff"}
        if extension == ".zip":
            with zipfile.ZipFile(directory / (stem + extension), "w") as archive:
                for name, content in members.items():
                    archive.writestr(name, content)
        else:
            with tarfile.open(directory / (stem + extension), "w:gz") as archive:
                for name, content in members.items():
                    info = tarfile.TarInfo(name)
                    info.size = len(content)
                    archive.addfile(info, io.BytesIO(content))


class MemoryDufs:
    """The real client still builds HTTP requests and streams request/response bodies."""

    def __init__(self):
        self.files = {}
        self.directories = set()
        self.unknown_entries = []
        self.requests = []
        self.failures = {}
        self.corrupt_downloads = False
        self.invalid_listing = False

    def open(self, request, timeout):
        parsed = urlsplit(request.full_url)
        method, path = request.get_method(), parsed.path
        body = request.data.read() if request.data else None
        authorization = request.get_header("Authorization")
        self.requests.append((method, path, authorization, body))
        status = self.failures.get((method, path), [])
        if status:
            raise HTTPError(request.full_url, status.pop(0), "do not echo secret", {}, io.BytesIO())
        if method == "GET" and parsed.query == "json":
            if self.invalid_listing:
                return io.BytesIO(b'{"unexpected": []}')
            entries = [{"name": name, "path_type": "Dir"} for name in sorted(self.directories)]
            return io.BytesIO(json.dumps({"paths": entries + self.unknown_entries}).encode())
        if method == "MKCOL":
            if path.startswith(publisher.ROOT) and path != publisher.ROOT:
                self.directories.add(path.removeprefix(publisher.ROOT).rstrip("/"))
            return io.BytesIO()
        if method == "PUT":
            if int(request.get_header("Content-length")) != len(body):
                raise AssertionError("incorrect streamed Content-Length")
            self.files[path] = body
            return io.BytesIO()
        if method == "GET":
            if path not in self.files:
                raise HTTPError(request.full_url, 404, "missing", {}, io.BytesIO())
            corrupt = self.corrupt_downloads and not path.endswith("/SHA256SUMS.txt")
            return io.BytesIO(self.files[path] + (b"corruption" if corrupt else b""))
        if method == "DELETE":
            self.directories.discard(path.removeprefix(publisher.ROOT).rstrip("/"))
            self.files = {name: body for name, body in self.files.items() if not name.startswith(path)}
            return io.BytesIO()
        raise AssertionError(f"Unexpected request: {method} {path}")


class PublisherTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.assets = Path(self.temporary.name)
        write_assets(self.assets)
        self.client = publisher.DufsClient("https://dufs.example", "test-user", "test-password")
        self.server = MemoryDufs()
        self.client.opener = self.server
        self.sleep = patch.object(publisher.time, "sleep")
        self.sleep.start()
        self.addCleanup(self.sleep.stop)
        self.output = patch("builtins.print")
        self.output.start()
        self.addCleanup(self.output.stop)

    def run_publish(self, command="upload"):
        publisher.publish(self.client, command, self.assets, CODE, VERSION, COMMIT)

    def deleted(self):
        return [path for method, path, _, _ in self.server.requests if method == "DELETE"]

    def completed_version(self, code):
        name = f"desktop-v{code}-{VERSION}"
        self.server.directories.add(name)
        self.server.files[publisher.ROOT + name + "/SHA256SUMS.txt"] = (
            self.assets / "SHA256SUMS.txt"
        ).read_bytes()
        return name

    def test_upload_verifies_every_file_anonymously_and_generates_checksums(self):
        self.run_publish()
        self.assertEqual(len(self.server.files), 7)
        checksum_lines = (self.assets / "SHA256SUMS.txt").read_text().splitlines()
        self.assertEqual(len(checksum_lines), 6)
        authenticated = "Basic " + base64.b64encode(b"test-user:test-password").decode()
        for method, path, auth, _ in self.server.requests:
            if method == "GET" and path.startswith(RELEASE_PATH):
                self.assertIsNone(auth)
            else:
                self.assertEqual(auth, authenticated)
        marker_index = next(index for index, (method, path, _, _) in enumerate(self.server.requests)
                            if method == "PUT" and path.endswith("/SHA256SUMS.txt"))
        verified_before_marker = [path for method, path, _, _ in self.server.requests[:marker_index]
                                  if method == "GET" and path.startswith(RELEASE_PATH)]
        self.assertEqual(len(verified_before_marker), 6)
        self.assertFalse(self.deleted())

    def test_transient_put_reopens_stream_and_rerun_is_idempotent(self):
        filename = sorted(self.assets.iterdir())[0].name
        path = RELEASE_PATH + filename
        self.server.failures[("PUT", path)] = [503]
        self.run_publish()
        bodies = [body for method, url, _, body in self.server.requests if method == "PUT" and url == path]
        self.assertEqual(bodies, [(self.assets / filename).read_bytes()] * 2)
        original = self.server.files.copy()
        self.server.requests.clear()
        self.run_publish()
        self.assertEqual(self.server.files, original)
        self.assertTrue(all(method == "GET" for method, _, _, _ in self.server.requests))

    def test_cleanup_keeps_two_numeric_versions_and_preserves_unmanaged_entries(self):
        self.run_publish()
        older = self.completed_version(9)
        previous = self.completed_version(10)
        unknown = {"manual-backup", f"desktop-v8-{VERSION}-backup", "desktop-v7-../../android"}
        self.server.directories.update({older, previous} | unknown)
        self.server.unknown_entries.append({"name": f"desktop-v3-{VERSION}", "path_type": "File"})
        self.run_publish("cleanup")
        self.assertEqual(self.deleted(), [publisher.ROOT + older + "/"])
        self.assertEqual(self.server.directories, {DIRECTORY, previous} | unknown)
        self.run_publish("cleanup")
        self.assertEqual(len(self.deleted()), 1)

    def test_partial_intermediate_version_does_not_replace_last_complete_version(self):
        self.run_publish()
        previous = self.completed_version(9)
        partial = f"desktop-v10-{VERSION}"
        self.server.directories.add(partial)
        self.run_publish("cleanup")
        self.assertEqual(self.deleted(), [publisher.ROOT + partial + "/"])
        self.assertEqual(self.server.directories, {DIRECTORY, previous})

    def test_existing_complete_release_with_different_local_bytes_cannot_be_overwritten(self):
        self.run_publish()
        self.server.requests.clear()
        with next(self.assets.glob("*.zip")).open("ab") as archive:
            archive.write(b"different bytes in otherwise valid zip")
        with self.assertRaisesRegex(publisher.PublishError, "different bytes"):
            self.run_publish()
        self.assertTrue(all(method == "GET" for method, _, _, _ in self.server.requests))

    def test_failed_public_verification_prevents_all_cleanup(self):
        self.run_publish()
        self.server.directories.update({f"desktop-v9-{VERSION}", f"desktop-v10-{VERSION}"})
        self.server.corrupt_downloads = True
        with self.assertRaisesRegex(publisher.PublishError, "Anonymous download"):
            self.run_publish("cleanup")
        self.assertFalse(self.deleted())

    def test_upload_public_verification_failure_is_not_success(self):
        self.server.corrupt_downloads = True
        with self.assertRaises(publisher.PublishError):
            self.run_publish()
        self.assertFalse(self.deleted())
        self.assertNotIn(RELEASE_PATH + "SHA256SUMS.txt", self.server.files)

    def test_newer_partial_release_allows_lower_version_upload(self):
        newer = f"desktop-v12-{VERSION}"
        self.server.directories.add(newer)
        self.run_publish()
        self.assertEqual(self.server.directories, {DIRECTORY, newer})
        self.assertIsNotNone(self.client.completion_checksums(DIRECTORY))
        self.assertEqual(len(self.server.files), 7)
        self.assertFalse(self.deleted())

    def test_newer_complete_release_allows_lower_version_upload_and_retry(self):
        publisher.prepare_assets(self.assets, CODE, VERSION, COMMIT)
        newer = self.completed_version(12)
        self.run_publish()
        self.server.requests.clear()
        self.run_publish()
        self.assertEqual(self.server.directories, {DIRECTORY, newer})
        self.assertIsNotNone(self.client.completion_checksums(DIRECTORY))
        self.assertTrue(all(method == "GET" for method, _, _, _ in self.server.requests))

    def test_same_version_code_different_name_is_rejected(self):
        self.server.directories.add(f"desktop-v{CODE}-2026.09.07-aaaaaaaa")
        with self.assertRaisesRegex(publisher.PublishError, "conflicting"):
            self.run_publish()
        self.assertFalse(self.server.files)

    def test_cleanup_keeps_lower_current_release_and_highest_other_complete_release(self):
        self.run_publish()
        older = self.completed_version(9)
        newer = self.completed_version(12)
        highest = self.completed_version(13)
        self.run_publish("cleanup")
        self.assertEqual(self.deleted(), [publisher.ROOT + name + "/" for name in (older, newer)])
        self.assertEqual(self.server.directories, {DIRECTORY, highest})
        self.assertIsNotNone(self.client.completion_checksums(DIRECTORY))
        self.run_publish("cleanup")
        self.assertEqual(len(self.deleted()), 2)

    def test_newer_release_appearing_before_delete_allows_cleanup(self):
        self.run_publish()
        older = self.completed_version(9)
        previous = self.completed_version(10)
        newer = f"desktop-v12-{VERSION}"
        directories = self.client.directories
        calls = 0

        def concurrent_listing(**kwargs):
            nonlocal calls
            calls += 1
            if calls == 3:
                self.server.directories.add(newer)
            return directories(**kwargs)

        with patch.object(self.client, "directories", side_effect=concurrent_listing):
            self.run_publish("cleanup")
        self.assertEqual(self.deleted(), [publisher.ROOT + older + "/"])
        self.assertEqual(self.server.directories, {DIRECTORY, previous, newer})

    def test_current_completion_marker_disappearing_prevents_cleanup(self):
        self.run_publish()
        self.completed_version(9)
        self.completed_version(10)
        completion_checksums = self.client.completion_checksums
        current_calls = 0

        def disappearing_marker(directory):
            nonlocal current_calls
            if directory == DIRECTORY:
                current_calls += 1
                if current_calls == 2:
                    return None
            return completion_checksums(directory)

        with patch.object(self.client, "completion_checksums", side_effect=disappearing_marker):
            with self.assertRaisesRegex(publisher.PublishError, "completion marker disappeared"):
                self.run_publish("cleanup")
        self.assertFalse(self.deleted())

    def test_missing_current_release_blocks_cleanup(self):
        with self.assertRaisesRegex(publisher.PublishError, "Current release directory is missing"):
            self.run_publish("cleanup")
        self.assertFalse(self.deleted())

    def test_manifest_target_mismatch_rejected_before_network(self):
        write_assets(self.assets, wrong_target=True)
        with self.assertRaisesRegex(publisher.PublishError, "does not match this release"):
            self.run_publish()
        self.assertFalse(self.server.requests)

    def test_candidate_or_missing_qualification_is_never_published(self):
        for tier in ("candidate", "preview", None):
            write_assets(self.assets, application_override={"supportTier": tier})
            with self.assertRaises(publisher.PublishError):
                self.run_publish()
        self.assertFalse(self.server.requests)

    def test_candidate_upload_is_isolated_and_includes_ubuntu_installers(self):
        write_assets(self.assets, application_override={"supportTier": "candidate"})
        for platform in ("linux-x86_64", "linux-aarch64"):
            (self.assets / f"topnode-desktop-{VERSION}-{platform}.deb").write_bytes(b"installer")

        url = publisher.upload_candidate(self.client, self.assets, CODE, VERSION, COMMIT, SOURCE_RUN_ID)
        expected = {CANDIDATE_PATH + asset.name for asset in self.assets.iterdir()}
        self.assertEqual(url, self.client.base_url + CANDIDATE_PATH)
        self.assertEqual(len(expected), 9)
        self.assertEqual(set(self.server.files), expected)
        writes = [path for method, path, _, _ in self.server.requests if method == "PUT"]
        self.assertEqual(writes[-1], CANDIDATE_PATH + "SHA256SUMS.txt")
        downloads = [path for method, path, auth, _ in self.server.requests if method == "GET" and auth is None]
        self.assertEqual(set(downloads), expected)
        self.assertFalse(self.deleted())

        self.server.requests.clear()
        publisher.upload_candidate(self.client, self.assets, CODE, VERSION, COMMIT, SOURCE_RUN_ID)
        self.assertTrue(all(method == "GET" for method, _, _, _ in self.server.requests))
        self.assertEqual(set(self.server.files), expected)

    def test_candidate_upload_requires_both_installers_and_candidate_manifests(self):
        for platform in ("linux-x86_64", "linux-aarch64"):
            installer = self.assets / f"topnode-desktop-{VERSION}-{platform}.deb"
            installer.write_bytes(b"installer")
        with self.assertRaisesRegex(publisher.PublishError, "does not match this release"):
            publisher.upload_candidate(self.client, self.assets, CODE, VERSION, COMMIT, SOURCE_RUN_ID)

        write_assets(self.assets, application_override={"supportTier": "candidate"})
        installer.unlink()
        with self.assertRaisesRegex(publisher.PublishError, "two Ubuntu installers"):
            publisher.upload_candidate(self.client, self.assets, CODE, VERSION, COMMIT, SOURCE_RUN_ID)
        self.assertFalse(self.server.requests)

    def test_manifest_version_and_commit_mismatch_rejected_before_network(self):
        for override in ({"versionCode": CODE + 1}, {"versionName": "other"}, {"gitCommit": "a" * 40}):
            with self.subTest(override=override):
                write_assets(self.assets, application_override=override)
                with self.assertRaisesRegex(publisher.PublishError, "does not match this release"):
                    self.run_publish()
        self.assertFalse(self.server.requests)

    def test_missing_and_extra_archives_rejected_before_network(self):
        extra = self.assets / "unrelated.zip"
        extra.write_bytes(b"unexpected")
        with self.assertRaisesRegex(publisher.PublishError, "exactly the six"):
            self.run_publish()
        extra.unlink()
        next(self.assets.glob("*.zip")).unlink()
        with self.assertRaisesRegex(publisher.PublishError, "exactly the six"):
            self.run_publish()
        self.assertFalse(self.server.requests)

    def test_invalid_directory_listing_fails_closed(self):
        self.server.invalid_listing = True
        with self.assertRaisesRegex(publisher.PublishError, "invalid directory listing"):
            self.run_publish()
        self.assertFalse(self.server.files)

    def test_redirects_and_auth_errors_fail_without_echoing_remote_error(self):
        for status in (302, 401, 403):
            with self.subTest(status=status):
                self.server.failures[("GET", publisher.ROOT)] = [status]
                with self.assertRaises(publisher.PublishError) as caught:
                    self.run_publish()
                self.assertEqual(str(caught.exception), f"dufs GET failed (HTTP {status})")
        self.assertIsNone(publisher.NoRedirect().redirect_request(None, None, 302, None, None,
                                                                 "https://other.example"))

    def test_retry_exhaustion_is_sanitized_and_never_deletes(self):
        self.server.failures[("GET", publisher.ROOT)] = [503] * 4
        with self.assertRaisesRegex(publisher.PublishError, "dufs GET failed \\(HTTP 503\\)"):
            self.run_publish()
        self.assertEqual(len(self.server.requests), 4)
        self.assertFalse(self.deleted())

    def test_invalid_version_and_url_rejected(self):
        for name in ("../outside", "2026.99.08-01234567", "2026.09.08-aaaaaaaa"):
            with self.subTest(name=name), self.assertRaises(publisher.PublishError):
                publisher.validate_release(CODE, name, COMMIT)
        for url in ("http://example.com", "https://user:password@example.com", "https://example.com/soft"):
            with self.subTest(url=url), self.assertRaises(publisher.PublishError):
                publisher.DufsClient(url, "user", "password")
        with self.assertRaises(publisher.PublishError):
            self.client.delete("../android")
        self.assertFalse(self.server.requests)


if __name__ == "__main__":
    unittest.main()
