"""Validate native evidence without inferring support from build tags."""
import hashlib
import json
from pathlib import Path

CAPABILITIES = {f"{transport}{trust}-uot-v2" for transport in ("https", "quic") for trust in ("", "-custom-ca")}
CHECKS = ("tcp", "udp_echo", "udp_dns", "negative_trust", "negative_auth")


def sha256(path):
    with Path(path).open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def validate_report(core, metadata, *, complete=True):
    path = core.parent / "naive-validation.json"
    if path.stat().st_size > 1024 * 1024:
        raise ValueError("Naive report exceeds size limit")
    report = json.loads(path.read_text(encoding="utf-8"))
    expected = {"schema_version": 2, "core_version": metadata["version"],
                "core_commit": metadata["commit"], "target": metadata["target"], "core_sha256": sha256(core)}
    if any(report.get(key) != value for key, value in expected.items()):
        raise ValueError("Naive report does not match this core, lock or architecture")
    caps = set(report["capabilities"])
    if not caps <= CAPABILITIES or (complete and caps != CAPABILITIES):
        raise ValueError("Naive release requires both transports, trust modes and UoT v2")
    for cap in caps:
        if not any(result.get("capability") == cap and all(result.get(check) is True for check in CHECKS)
                   for result in report["results"]):
            raise ValueError("Naive capability lacks matching successful native evidence")
    libraries = report["libraries"]
    expected_libraries = metadata.get("libraries", [])
    if libraries != expected_libraries:
        raise ValueError("Naive dependencies differ from build metadata")
    required = {"windows": "libcronet.dll", "linux": "libcronet.so"}.get(metadata["goos"])
    if required and not any(lib.get("file") == required for lib in libraries):
        raise ValueError("Naive core is missing its Cronet dependency")
    seen = set()
    for library in libraries:
        name = library["file"]
        if not name or name.startswith(".") or any(char in name for char in "/\\:") or name in seen:
            raise ValueError("Invalid Naive library filename")
        seen.add(name)
        if sha256(core.parent / name) != library["sha256"]:
            raise ValueError("Naive library digest mismatch")
    return report
