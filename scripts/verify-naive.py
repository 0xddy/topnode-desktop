#!/usr/bin/env python3
"""Exercise a Naive test core over loopback without changing system trust."""

import argparse
import hashlib
import struct

from naive_qualification import sha256
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from http.client import HTTPConnection, HTTPException
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
import secrets
import socket
import subprocess
import tempfile
from threading import Thread
import time

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID


HOST = "127.0.0.1"
SERVER_NAME = "naive.test"


def certificate(name, issuer=None, *, ca=False, expired=False):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name)])
    issuer_cert, issuer_key = issuer or (None, key)
    now = datetime.now(timezone.utc)
    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer_cert.subject if issuer_cert else subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=2))
        .not_valid_after(now + timedelta(days=-1 if expired else 1))
        .add_extension(x509.BasicConstraints(ca=ca, path_length=None), critical=True)
    )
    if not ca:
        builder = builder.add_extension(
            x509.SubjectAlternativeName([x509.DNSName(name)]), critical=False,
        ).add_extension(
            x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False,
        )
    return builder.sign(issuer_key, hashes.SHA256()), key


def pem(cert):
    return cert.public_bytes(serialization.Encoding.PEM).decode()


def free_port(kind):
    with socket.socket(type=kind) as listener:
        listener.bind((HOST, 0))
        return listener.getsockname()[1]


@contextmanager
def core_process(binary, config, port):
    with tempfile.TemporaryFile() as diagnostics, subprocess.Popen(
        [binary, "run", "-c", "stdin"], stdin=subprocess.PIPE,
        stdout=diagnostics, stderr=diagnostics,
    ) as process:
        try:
            process.stdin.write(json.dumps(config).encode())
            process.stdin.close()
            deadline = time.monotonic() + 10
            while time.monotonic() < deadline and process.poll() is None:
                try:
                    with socket.create_connection((HOST, port), timeout=0.2):
                        break
                except OSError:
                    time.sleep(0.05)
            else:
                diagnostics.seek(0)
                raise RuntimeError("Naive test core failed to start; diagnostics may contain test credentials")
            yield
            if process.poll() is not None:
                raise RuntimeError("Naive test core exited during the request")
        finally:
            if process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    process.kill()


def request_through_proxy(binary, transport, server_cert, key, trust, name, password, origin):
    naive_port = free_port(socket.SOCK_DGRAM if transport == "quic" else socket.SOCK_STREAM)
    proxy_port = free_port(socket.SOCK_STREAM)
    while proxy_port == naive_port:
        proxy_port = free_port(socket.SOCK_STREAM)
    test_password = "loopback-only"
    config = {
        "log": {"level": "warn"},
        "inbounds": [
            {
                "type": "naive", "tag": "server", "listen": HOST, "listen_port": naive_port,
                "network": "udp" if transport == "quic" else "tcp",
                "users": [{"username": "probe", "password": test_password}],
                "tls": {
                    "enabled": True, "certificate": [pem(server_cert)],
                    "key": [key.private_bytes(
                        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                        serialization.NoEncryption(),
                    ).decode()],
                },
            },
            {"type": "mixed", "tag": "client", "listen": HOST, "listen_port": proxy_port},
        ],
        "outbounds": [
            {"type": "direct", "tag": "direct"},
            {
                "type": "naive", "tag": "tunnel", "server": HOST, "server_port": naive_port,
                "username": "probe", "password": password or test_password, "quic": transport == "quic",
                "udp_over_tcp": {"enabled": True, "version": 2},
                "tls": {"enabled": True, "server_name": name, **({"certificate": [pem(trust)]} if trust else {})},
            },
        ],
        "route": {"rules": [{"inbound": ["client"], "action": "route", "outbound": "tunnel"}], "final": "direct"},
    }
    with core_process(binary, config, proxy_port):
        connection = HTTPConnection(HOST, proxy_port, timeout=8)
        try:
            address = f"{HOST}:{origin.server_port}"
            connection.request("GET", f"http://{address}/", headers={"Host": address})
            with connection.getresponse() as response:
                ok = response.status == 200 and response.read() == origin.body
                if ok:
                    verify_udp_echo(proxy_port)
                return ok
        except (OSError, HTTPException):
            return False
        finally:
            connection.close()


def read_exact(stream, length):
    result = bytearray()
    while len(result) < length:
        part = stream.recv(length - len(result))
        if not part:
            raise RuntimeError("SOCKS control connection closed")
        result.extend(part)
    return bytes(result)


def socks_udp(proxy_port, destination, payload):
    with socket.create_connection((HOST, proxy_port), timeout=8) as control:
        control.sendall(bytes([5, 1, 0]))
        if read_exact(control, 2) != bytes([5, 0]):
            raise RuntimeError("SOCKS greeting failed")
        control.sendall(bytes([5, 3, 0, 1, 0, 0, 0, 0, 0, 0]))
        header = read_exact(control, 4)
        if header[:3] != bytes([5, 0, 0]) or header[3] not in (1, 4):
            raise RuntimeError("SOCKS UDP association failed")
        family = socket.AF_INET if header[3] == 1 else socket.AF_INET6
        relay = socket.inet_ntop(family, read_exact(control, 4 if family == socket.AF_INET else 16))
        port = struct.unpack("!H", read_exact(control, 2))[0]
        host, destination_port = destination
        encoded = host.encode("ascii")
        packet = bytes([0, 0, 0, 3, len(encoded)]) + encoded + struct.pack("!H", destination_port) + payload
        with socket.socket(family, socket.SOCK_DGRAM) as udp:
            udp.settimeout(8)
            udp.connect((HOST if relay == "0.0.0.0" else relay, port))
            udp.send(packet)
            reply = udp.recv(65535)
        if len(reply) < 10 or reply[:3] != bytes(3):
            raise RuntimeError("Invalid SOCKS UDP response")
        offset = {1: 10, 4: 22}.get(reply[3])
        if reply[3] == 3:
            offset = 7 + reply[4]
        if offset is None or len(reply) < offset:
            raise RuntimeError("Invalid SOCKS UDP address")
        return reply[offset:]


def verify_udp_echo(proxy_port):
    with socket.socket(type=socket.SOCK_DGRAM) as echo:
        echo.bind((HOST, 0))
        echo.settimeout(10)
        sizes = (0, 1, 1200, 8192)
        def serve():
            try:
                for _ in sizes:
                    payload, peer = echo.recvfrom(65535)
                    echo.sendto(payload, peer)
            except OSError:
                pass
        worker = Thread(target=serve, daemon=True)
        worker.start()
        for size in sizes:
            payload = secrets.token_bytes(size)
            if socks_udp(proxy_port, echo.getsockname(), payload) != payload:
                raise RuntimeError(f"UoT echo failed for {size} bytes")
        worker.join(timeout=1)
    # A DNS datagram is checked independently from echo framing.
    with socket.socket(type=socket.SOCK_DGRAM) as dns:
        dns.bind((HOST, 0))
        dns.settimeout(10)
        query = secrets.token_bytes(2) + bytes.fromhex("01000001000000000000046e6169766504746573740000010001")
        expected = query[:2] + bytes.fromhex("81830001000000000000") + query[12:]
        def resolve():
            try:
                data, peer = dns.recvfrom(65535)
                if data == query:
                    dns.sendto(expected, peer)
            except OSError:
                pass
        Thread(target=resolve, daemon=True).start()
        if socks_udp(proxy_port, dns.getsockname(), query) != expected:
            raise RuntimeError("UoT UDP DNS failed")


def verify_system_fixture(binary, fixture):
    capabilities = set()
    for case in fixture["cases"]:
        transport = case["transport"]
        if transport not in ("https", "quic"):
            raise ValueError("Invalid native fixture transport")
        outbound = dict(case["outbound"], tag="proxy")
        tls = outbound["tls"]
        if (outbound["type"] != "naive" or outbound.get("quic", False) != (transport == "quic")
            or tls.get("enabled") is not True or tls.get("insecure", False) is not False
            or "certificate" in tls or "certificate_path" in tls
            or outbound.get("udp_over_tcp") != {"enabled": True, "version": 2}):
            raise ValueError("System trust fixture must use verified TLS and UoT v2")
        port = free_port(socket.SOCK_STREAM)
        config = {"log":{"disabled":True}, "inbounds":[{"type":"mixed","listen":HOST,"listen_port":port}],
                  "outbounds":[outbound],"route":{"final":"proxy"}}
        with core_process(binary, config, port):
            connection = HTTPConnection(HOST, port, timeout=15)
            try:
                connection.request("GET", case["url"])
                response = connection.getresponse()
                if response.status != 200 or response.read().decode() != case["expected_body"]:
                    raise RuntimeError("System trust TCP probe failed")
            finally:
                connection.close()
            probes = case["udp_probes"]
            if not {"echo-empty","echo-small","echo-1200","echo-large","dns"} <= {p["kind"] for p in probes}:
                raise ValueError("System trust fixture lacks UDP matrix")
            for probe in probes:
                if socks_udp(port, (probe["host"], probe["port"]), bytes.fromhex(probe["request_hex"])) != bytes.fromhex(probe["response_hex"]):
                    raise RuntimeError("System trust UDP probe failed")
        capabilities.add(f"{transport}-uot-v2")
    return capabilities


class Origin(BaseHTTPRequestHandler):
    def do_GET(self):
        body = self.server.body
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *_args):
        pass


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--core", type=Path, required=True)
    parser.add_argument("--metadata", type=Path, help="source.json from the exact core build")
    parser.add_argument("--report", type=Path, help="write native evidence, including incomplete qualification")
    parser.add_argument("--system-fixture", type=Path, help="isolated public-CA endpoints with node-only UDP targets")
    args = parser.parse_args()
    binary = args.core.resolve(strict=True)
    ca = certificate("Desktop Naive test CA", ca=True)
    leaf, leaf_key = certificate(SERVER_NAME, ca)
    self_signed, self_key = certificate(SERVER_NAME)
    expired, expired_key = certificate(SERVER_NAME, ca, expired=True)
    other_ca, _ = certificate("Wrong Naive test CA", ca=True)
    cases = (
        ("private-ca", leaf, leaf_key, ca[0], SERVER_NAME, None, True),
        ("self-signed", self_signed, self_key, self_signed, SERVER_NAME, None, True),
        ("system-rejects-private-ca", leaf, leaf_key, None, SERVER_NAME, None, False),
        ("wrong-ca", leaf, leaf_key, other_ca, SERVER_NAME, None, False),
        ("expired", expired, expired_key, ca[0], SERVER_NAME, None, False),
        ("wrong-name", leaf, leaf_key, ca[0], "wrong.naive.test", None, False),
        ("wrong-password", leaf, leaf_key, ca[0], SERVER_NAME, "incorrect", False),
    )
    failures = []
    with ThreadingHTTPServer((HOST, 0), Origin) as origin:
        origin.body = secrets.token_hex(16).encode()
        Thread(target=origin.serve_forever, daemon=True).start()
        try:
            for transport in ("https", "quic"):
                for case, cert, key, trust, name, password, expected in cases:
                    actual = request_through_proxy(binary, transport, cert, key, trust, name, password, origin)
                    label = f"{transport}-{case}"
                    print(f"{label} {'PASS' if actual == expected else 'FAIL'}", flush=True)
                    if actual != expected:
                        failures.append(label)
        finally:
            origin.shutdown()
    if failures:
        raise SystemExit(f"Naive checks failed: {', '.join(failures)}")
    capabilities = verify_system_fixture(binary, json.loads(args.system_fixture.read_text(encoding="utf-8"))) if args.system_fixture else set()
    # A custom-CA offer also matches system-trust endpoints at the panel, so
    # never advertise it until that transport's system trust has been tested.
    capabilities |= {cap.replace("-uot-v2", "-custom-ca-uot-v2") for cap in list(capabilities)}
    if args.report:
        if not args.metadata:
            parser.error("--report requires --metadata")
        metadata = json.loads(args.metadata.read_text(encoding="utf-8"))
        version = subprocess.check_output([binary,"version"],text=True,timeout=10)
        if f"sing-box version {metadata['version']}" not in version.splitlines() or f"Revision: {metadata['commit']}" not in version.splitlines():
            raise RuntimeError("Native core identity does not match build metadata")
        if sha256(binary) != metadata["binarySha256"]:
            raise RuntimeError("Native core changed after build")
        libraries = metadata.get("libraries", [])
        for library in libraries:
            if sha256(binary.parent / library["file"]) != library["sha256"]:
                raise RuntimeError("Native dependency changed after build")
        report = {"schema_version":2,"core_version":metadata["version"],"core_commit":metadata["commit"],
                  "target":metadata["target"],"core_sha256":sha256(binary),"libraries":libraries,
                  "verified_at":datetime.now(timezone.utc).isoformat(),"capabilities":sorted(capabilities),
                  "results":[dict(capability=cap,tcp=True,udp_echo=True,udp_dns=True,negative_trust=True,negative_auth=True) for cap in sorted(capabilities)],
                  "loopback_cases":[f"{transport}-{case[0]}" for transport in ("https","quic") for case in cases],
                  "system_takeover":"not-tested"}
        args.report.write_text(json.dumps(report,indent=2)+"\n",encoding="utf-8")
    if not capabilities:
        print("Loopback TCP/UoT/DNS passed; system trust and system takeover remain unqualified.")


if __name__ == "__main__":
    main()
