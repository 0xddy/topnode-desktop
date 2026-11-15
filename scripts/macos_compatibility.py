"""Deployment targets and checks for the native macOS executables we ship."""

from pathlib import Path
import struct


DEPLOYMENT_TARGETS = {
    "x86_64-apple-darwin": "12.0",
    "aarch64-apple-darwin": "13.0",
}
CPU_TYPES = {"x86_64-apple-darwin": 0x01000007, "aarch64-apple-darwin": 0x0100000C}


def verify_binary(path: Path, target: str) -> str:
    """Reject a wrong-architecture or newer-OS binary before it enters a package."""
    with path.open("rb") as stream:
        header = stream.read(32)
        if len(header) != 32 or header[:4] != b"\xcf\xfa\xed\xfe":
            raise RuntimeError(f"{path.name}: expected a native 64-bit Mach-O executable")
        _, cpu, _, file_type, count, size, _, _ = struct.unpack("<8I", header)
        if cpu != CPU_TYPES[target] or file_type != 2:
            raise RuntimeError(f"{path.name}: unexpected Mach-O architecture or file type for {target}")
        if size > 1024 * 1024:
            raise RuntimeError(f"{path.name}: invalid Mach-O load command size")
        commands = stream.read(size)
    if len(commands) != size:
        raise RuntimeError(f"{path.name}: truncated Mach-O load commands")
    position = 0
    versions = []
    for _ in range(count):
        if position + 8 > size:
            raise RuntimeError(f"{path.name}: truncated Mach-O load command")
        command, length = struct.unpack_from("<2I", commands, position)
        if length < 8 or position + length > size:
            raise RuntimeError(f"{path.name}: invalid Mach-O load command")
        if command == 0x32:  # LC_BUILD_VERSION
            if length < 24 or struct.unpack_from("<I", commands, position + 8)[0] != 1:
                raise RuntimeError(f"{path.name}: expected a macOS build version")
            versions.append(struct.unpack_from("<I", commands, position + 12)[0])
        elif command == 0x24:  # LC_VERSION_MIN_MACOSX
            if length < 16:
                raise RuntimeError(f"{path.name}: invalid macOS version command")
            versions.append(struct.unpack_from("<I", commands, position + 8)[0])
        position += length
    if position != size or len(versions) != 1:
        raise RuntimeError(f"{path.name}: expected one macOS minimum version")
    encoded = versions[0]
    minimum = (encoded >> 16, (encoded >> 8) & 255, encoded & 255)
    allowed = tuple(map(int, DEPLOYMENT_TARGETS[target].split("."))) + (0,)
    minimum_text = ".".join(map(str, minimum))
    if minimum > allowed:
        raise RuntimeError(f"{path.name}: requires macOS {minimum_text}, target is {DEPLOYMENT_TARGETS[target]}")
    return minimum_text
